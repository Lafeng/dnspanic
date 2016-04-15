package main

import (
	"fmt"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/miekg/dns"
)

type rrcache struct {
	cache *lrucache.LRUCache
}

func newRRCache() *rrcache {
	return &rrcache{
		cache: lrucache.NewLRUCache(1024),
	}
}

func msgKey(m *dns.Msg) string {
	q := m.Question[0]
	return fmt.Sprintf("%s%d%d", q.Name, q.Qclass, q.Qtype)
}

func (c *rrcache) get(req *dns.Msg) *dns.Msg {
	v, found := c.cache.GetNotStale(msgKey(req))
	if found {
		return v.(*dns.Msg).Copy()
	} else {
		return nil
	}
}

func (c *rrcache) set(resp *dns.Msg, lshift uint) {
	var expiry uint32 = 3600
	for _, rr := range resp.Answer {
		ttl := rr.Header().Ttl
		if ttl > 0 && ttl < expiry {
			expiry = ttl
		}
	}
	if expiry <= 2 { // special case for dubious item
		expiry = 300
	} else {
		expiry <<= lshift
	}
	c.cache.Set(msgKey(resp), resp, time.Now().Add(time.Duration(expiry)*1e9))
}
