package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var (
	conf *config
	rrc  *rrcache
)

func main() {
	var (
		localAddr string
		cfgPath   string
		formatCfg bool
	)
	flag.StringVar(&localAddr, "l", ":53", "local listen address")
	flag.StringVar(&cfgPath, "c", "config.conf", "config file path")
	flag.BoolVar(&formatCfg, "format", false, "format config file")
	flag.Parse()
	rrc = newRRCache()
	conf = new(config)
	if err := initialConfig(cfgPath, conf); err != nil {
		log.Fatalln(err)
	}
	if formatCfg {
		if err := formatConfig(cfgPath); err != nil {
			log.Fatalln(err)
		}
		return
	}

	var failure = make(chan error, 2)
	var udpServer, tcpServer dns.Server
	var handler proxyHandler
	udpServer.Net = "udp"
	tcpServer.Net = "tcp"
	udpServer.Handler = handler
	tcpServer.Handler = handler
	udpServer.Addr = localAddr
	tcpServer.Addr = localAddr

	go func() { failure <- udpServer.ListenAndServe() }()
	go func() { failure <- tcpServer.ListenAndServe() }()

	log.Println("Ready for serving dns on udp/tcp", localAddr)
	waitSignal(failure)

	// waiting for shutdown
	go func() { failure <- tcpServer.Shutdown() }()
	go func() { failure <- udpServer.Shutdown() }()
	<-failure
	<-failure
}

type proxyHandler struct{}

func (h proxyHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req.MsgHdr.Response == true || len(req.Question) == 0 { // supposed responses sent to us are bogus
		return
	}
	if cc := rrc.get(req); cc != nil {
		cc.Id = req.Id
		w.WriteMsg(cc)
		return
	}

	entry := conf.findEntry(req.Question[0].Name)

	var nextReq dns.Msg
	nextReq.Id = dns.Id()
	nextReq.RecursionDesired = true
	nextReq.Question = req.Question

	var result = make(chan *dns.Msg, len(entry.backends))
	var progress = make(chan byte, len(entry.backends))
	defer close(progress)

	go asyncQuery(entry.backends, &nextReq, result, progress)

	var resultMsg *dns.Msg
	for i := 0; i < cap(progress); i++ {
		if i >= 1 {
			progress <- 1
		}
		select {
		case resultMsg = <-result:
			if resultMsg == nil {
				continue
			}
		case <-time.After(_TIMEOUT):
			log.Println("waiting response timeout")
			continue
		}

		resultRR := resultMsg.Answer
		if len(resultRR) > 0 && entry.filters != nil {
			// apply filters
			for _, f := range entry.filters {
				resultRR = f.filter(resultRR)
			}
			// all RRs were filtered
			if len(resultRR) == 0 {
				resultMsg = nil
				continue
			}
		}
		// write back RRs
		resultMsg.Answer = resultRR
		break
	}
	if resultMsg != nil {
		rrc.set(resultMsg)
		resultMsg.Id = req.Id
		w.WriteMsg(resultMsg)
	} else {
		log.Println("no response")
	}
}

func waitSignal(end chan error) {
	var endCount int
	var sigChan = make(chan os.Signal)
	USR2 := syscall.Signal(12) // fake signal-USR2 for windows
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, USR2)

	for {
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
				log.Println("Terminated by", sig)
				return
			default:
				log.Println("Ingore signal", sig)
			}

		case err := <-end:
			endCount++
			switch endCount {
			case 1:
				log.Println(err)
			default:
				return
			}
		}
	}
}
