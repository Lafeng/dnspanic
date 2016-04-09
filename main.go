package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

var (
	conf *config
	rrc  *rrcache
	qclt *qClient
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
	qclt = newQClient()
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
	udpServer.DecorateReader = func(r dns.Reader) dns.Reader {
		return &decoratedIdleReader{Reader: r}
	}

	go func() { failure <- udpServer.ListenAndServe() }()
	go func() { failure <- tcpServer.ListenAndServe() }()

	log.Println("Ready for serving dns on udp/tcp", localAddr)
	waitSignal(failure)

	go func() { failure <- tcpServer.Shutdown() }()
	go func() { failure <- udpServer.Shutdown() }()
	qclt.shutdown()
	// waiting for shutdown
	<-failure
	<-failure
}

type decoratedIdleReader struct {
	dns.Reader
	idleCnt int
}

func (dr *decoratedIdleReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	return nil, nil
}

func (dr *decoratedIdleReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) (b []byte, s *dns.SessionUDP, e error) {
	b, s, e = dr.Reader.ReadUDP(conn, timeout)
	if ne, y := e.(*net.OpError); y && ne.Timeout() {
		dr.idleCnt++
		if dr.idleCnt&3 == 3 {
			go qclt.cleanup()
		}
	}
	return
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

	var resultMsg *dns.Msg
	var nextReq dns.Msg
	nextReq.Id = dns.Id()
	nextReq.RecursionDesired = true
	nextReq.Question = req.Question

nextQuery:
	for _, be := range entry.backends {
		tx := newTransaction(&nextReq, entry.filters)
		qclt.query(be, tx)
		select {
		case resultMsg = <-tx.result:
			if resultMsg != nil {
				break nextQuery
			}
		case <-time.After(_TIMEOUT_S):
			continue
		}
	}

	if resultMsg != nil {
		rrc.set(resultMsg, 0)
		resultMsg.Id = req.Id
		w.WriteMsg(resultMsg)
	} else {
		log.Println("no response for", req.Question[0].Name)
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
