package main

import (
	"log"
	"time"

	"github.com/miekg/dns"
)

const (
	TIMEOUT = time.Second
)

var (
	clientTCP dns.Client
	clientUDP dns.Client
)

func init() {
	clientTCP.Net = "tcp"
	clientTCP.ReadTimeout = TIMEOUT
	clientTCP.WriteTimeout = TIMEOUT

	clientUDP.Net = "udp"
	clientUDP.ReadTimeout = TIMEOUT
	clientUDP.WriteTimeout = TIMEOUT
}

type backendSet map[string][]*backend

type backend struct {
	net  string
	addr string // with :port
}

func (b *backend) singleQuery(req *dns.Msg, result chan *dns.Msg) {
	var client *dns.Client
	switch b.net {
	case "udp":
		client = &clientUDP
	case "tcp":
		client = &clientTCP
	}
	msg, rtt, err := client.Exchange(req, b.addr)

	q := req.Question[0]
	if err == nil {
		log.Printf("Query [%s]%s @%s/%s rtt=%d answers=%d", q.Name, dns.TypeToString[q.Qtype], b.net, b.addr, rtt/1e6, len(msg.Answer))
	} else {
		log.Printf("Query [%s]%s @%s/%s err=%v", q.Name, dns.TypeToString[q.Qtype], b.net, b.addr, err)
	}

	select {
	case result <- msg:
	case <-time.After(time.Millisecond * 100):
	}
}

func asyncQuery(backends []*backend, req *dns.Msg, result chan *dns.Msg, progress <-chan byte) {
	for i, be := range backends {
		if i == 0 {
			go be.singleQuery(req, result)
		} else {
			switch <-progress {
			case 1:
				go be.singleQuery(req, result)
			case 0:
				return
			}
		}
	}
}
