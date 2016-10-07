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
	_TIMEOUT_1 = time.Millisecond * 500
	_TIMEOUT_2 = time.Millisecond * 300
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

func (tx *transaction) newTransaction(req *dns.Msg, filters []filter) *transaction {
	_tx := &transaction{
		req:     req,
		created: time.Now().Unix(),
		filters: filters,
	}
	if tx == nil {
		_tx.result = make(chan *dns.Msg, 1)
	} else {
		_tx.result = tx.result
	}
	return _tx
}

func (t *transaction) reply(msg *dns.Msg, rtt int, err error, be *backend) {
	var cnt int32
	if msg != nil && msg.Response {
		cnt = atomic.AddInt32(&t.replCnt, 1)
		if msg.Len() > 512 {
			// Simply use dns compress to prevent the message larger than 512-bytes
			msg.Compress = true
		}
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
			msg = applyFilters(msg, t.filters)
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
		// should filter second response
		msg = applyFilters(msg, conf.global.filters)
		if msg != nil {
			rrc.set(msg, 1)
		}
	}
}

func applyFilters(msg *dns.Msg, filters []filter) *dns.Msg {
	var rrset = msg.Answer
	// apply filters
	for _, f := range filters {
		rrset = f.filter(rrset, msg)
	}
	// all RRs were filtered
	if len(rrset) == 0 {
		msg = nil
	} else { // write back
		msg.Answer = rrset
	}
	return msg
}

// weak equivalent
func rrhdrEquals(a, b *dns.RR_Header) bool {
	return a.Class == b.Class && a.Rrtype == b.Rrtype && a.Rdlength == b.Rdlength
}

var opt_hdr = []dns.RR{
	&dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
			Class:  dns.DefaultMsgSize,
		},
	},
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
	return q.createConnection(be, false)
}

// udp connection
func (q *qClient) createConnection(be *backend, force bool) (*dns.Conn, error) {
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

	var conn = &dns.Conn{Conn: udpConn}
	var existed bool
	q.cmu.Lock()
	// recheck map whether the connection has been created.
	if old, y := q.conns[be.url]; y {
		if force {
			// close old then put new
			old.Close()
		} else {
			// reuse old
			existed = true
			udpConn.Close()
			conn = old
		}
	}
	if !existed {
		q.conns[be.url] = conn
		go q.listen(conn, be)
	}
	q.cmu.Unlock()
	return conn, nil
}

func (q *qClient) listen(conn *dns.Conn, be *backend) {
	var msg *dns.Msg
	var err error

	for {
		msg, err = conn.ReadMsg()
		if msg != nil {
			txKey := fmt.Sprint(be.url, msg.Id)
			q.tmu.RLock()
			tx := q.txMap[txKey]
			q.tmu.RUnlock()
			if tx != nil {
				tx.reply(msg, getRtt(conn), err, be)
			}
		} else if _, y := err.(*net.OpError); y {
			conn.Close()
			time.Sleep(time.Second)
			log.Printf("listen remote=%s error=%s", be.addr, err)
			break
		}
	}
	// recreate connection and start listening
	for {
		conn, err = q.createConnection(be, true)
		if conn != nil {
			break
		} else {
			log.Println("create connection remote=%s error=%s", be.addr, err)
			time.Sleep(time.Second * 2)
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
		conn, err = dns.DialTimeout(be.net, be.addr, _TIMEOUT_1)
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
	conn.SetWriteDeadline(time.Now().Add(_TIMEOUT_1))
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
