package main

import (
	"container/list"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

const (
	_TIMEOUT   = time.Second
	_TIMEOUT_S = _TIMEOUT >> 1
)

type backendSet map[string][]*backend

type backend struct {
	net  string
	addr string // with :port
	url  string
}

type transaction struct {
	result  chan *dns.Msg
	lastMsg *dns.Msg
	req     *dns.Msg
	filters []filter
	created int64
	replCnt int32
	txKey   string // proto+addr+id
}

func newTransaction(req *dns.Msg, filters []filter) *transaction {
	return &transaction{
		result:  make(chan *dns.Msg, 1),
		req:     req,
		created: time.Now().Unix(),
		filters: filters,
	}
}

func (t *transaction) reply(msg *dns.Msg, rtt int, err error, be *backend) {
	var cnt int32
	if msg != nil && msg.Response {
		cnt = atomic.AddInt32(&t.replCnt, 1)
	}

	if cnt == 1 {
		t.lastMsg = msg
		var q = t.req.Question[0]
		if err == nil {
			log.Printf("Query [%s %s] @%s rtt=%d answers=%d", q.Name, dns.TypeToString[q.Qtype], be.url, rtt, len(msg.Answer))
		} else {
			log.Printf("Query [%s %s] @%s rtt=%d err=%v", q.Name, dns.TypeToString[q.Qtype], be.url, rtt, err)
		}

		if msg != nil && len(msg.Answer) > 0 {
			var rrset = msg.Answer
			// apply filters
			for _, f := range t.filters {
				rrset = f.filter(rrset)
			}
			// all RRs were filtered
			if len(rrset) == 0 {
				t.lastMsg = nil
				msg = nil
			} else { // write back
				msg.Answer = rrset
			}
		}
		// feedback
		select {
		case t.result <- msg:
		default:
		}

	} else if cnt > 1 && len(msg.Answer) > 0 {
		if lastMsg := t.lastMsg; lastMsg != nil {
			log.Printf("recv-%d record %s\n previous record %s may be dirty", cnt, msg.Answer, lastMsg.Answer)
		}
		rrc.set(msg, 1)
	}
}

// weak equivalent
func rrhdrEquals(a, b *dns.RR_Header) bool {
	return a.Class == b.Class && a.Rrtype == b.Rrtype && a.Rdlength == b.Rdlength
}

type qClient struct {
	cmu     sync.RWMutex
	tmu     sync.RWMutex
	txQueue *list.List
	conns   map[string]*dns.Conn
	txMap   map[string]*transaction
}

func newQClient() *qClient {
	return &qClient{
		txQueue: list.New(),
		conns:   make(map[string]*dns.Conn),
		txMap:   make(map[string]*transaction),
	}
}

func (q *qClient) shutdown() {
	q.cmu.Lock()
	defer q.cmu.Unlock()
	for _, conn := range q.conns {
		conn.Close()
	}
}

// get or create
func (q *qClient) getConnection(be *backend) (*dns.Conn, error) {
	q.cmu.RLock()
	if conn, y := q.conns[be.url]; y {
		q.cmu.RUnlock()
		return conn, nil
	}
	q.cmu.RUnlock()
	lAddr, err := net.ResolveUDPAddr(be.net, ":0")
	if err != nil {
		return nil, err
	}
	rAddr, err := net.ResolveUDPAddr(be.net, be.addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.DialUDP(be.net, lAddr, rAddr)
	if err != nil {
		return nil, err
	}
	conn := &dns.Conn{Conn: udpConn}
	q.cmu.Lock()
	q.conns[be.url] = conn
	q.cmu.Unlock()
	go q.listen(conn, be)
	return conn, nil
}

func (q *qClient) listen(conn *dns.Conn, be *backend) {
	for {
		m, err := conn.ReadMsg()
		if m != nil {
			txKey := fmt.Sprint(be.url, m.Id)
			q.tmu.RLock()
			tx := q.txMap[txKey]
			q.tmu.RUnlock()
			if tx != nil {
				tx.reply(m, getRtt(conn), err, be)
			}
		} else if _, y := err.(*net.OpError); y {
			return
		}
	}
}

func (q *qClient) requestOverTcp(conn *dns.Conn, be *backend) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(_TIMEOUT))
	m, err := conn.ReadMsg()
	if m != nil {
		txKey := fmt.Sprint(be.url, m.Id)
		q.tmu.RLock()
		tx := q.txMap[txKey]
		q.tmu.RUnlock()
		if tx != nil {
			tx.reply(m, getRtt(conn), err, be)
		}
	}
}

type miekgConn struct {
	net.Conn                         // a net.Conn holding the connection
	UDPSize        uint16            // minimum receive buffer for UDP messages
	TsigSecret     map[string]string // secret(s) for Tsig map[<zonename>]<base64 secret>, zonename must be fully qualified
	rtt            time.Duration
	t              time.Time
	tsigRequestMAC string
}

func getRtt(c *dns.Conn) int {
	mc := (*miekgConn)(unsafe.Pointer(c))
	return int(mc.rtt / 1e6)
}

func (q *qClient) query(be *backend, tx *transaction) {
	var conn *dns.Conn
	var isTcpConn bool
	var err error
	if strings.HasPrefix(be.net, "udp") {
		conn, err = q.getConnection(be)
	} else {
		conn, err = dns.DialTimeout(be.net, be.addr, _TIMEOUT_S)
		isTcpConn = true
	}

	if conn == nil {
		tx.reply(nil, 0, err, be)
		return
	}

	req := tx.req
	txKey := fmt.Sprint(be.url, req.Id)
	q.tmu.Lock()
	tx.txKey = txKey
	q.txMap[txKey] = tx
	q.txQueue.PushBack(tx)
	q.tmu.Unlock()

	if isTcpConn {
		go q.requestOverTcp(conn, be)
	}
	conn.SetWriteDeadline(time.Now().Add(_TIMEOUT_S))
	conn.WriteMsg(req)
	return
}

func (q *qClient) cleanup() {
	q.tmu.Lock()
	defer q.tmu.Unlock()
	now := time.Now().Unix()
	for e := q.txQueue.Front(); e != nil; {
		tx := e.Value.(*transaction)
		if now-tx.created > 3 {
			next := e.Next()
			q.txQueue.Remove(e)
			delete(q.txMap, tx.txKey)
			e = next
		} else {
			break
		}
	}
}
