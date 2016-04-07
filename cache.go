package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type rrcache struct {
	cache *cache.Cache
}

func newRRCache() *rrcache {
	return &rrcache{
		cache: cache.New(time.Minute*5, time.Second*30),
	}
}

func msgKey(m *dns.Msg) string {
	q := m.Question[0]
	return fmt.Sprintf("%s%d%d", q.Name, q.Qclass, q.Qtype)
}

func (c *rrcache) get(req *dns.Msg) *dns.Msg {
	v, found := c.cache.Get(msgKey(req))
	if found {
		return v.(*dns.Msg).Copy()
	} else {
		return nil
	}
}

func (c *rrcache) set(resp *dns.Msg) {
	var expiry uint32 = 0xffFFffFF
	for _, rr := range resp.Answer {
		ttl := rr.Header().Ttl
		if ttl > 0 && ttl < expiry {
			expiry = ttl
		}
	}
	if expiry > 3600 {
		expiry = 3600
	}
	c.cache.Set(msgKey(resp), resp, time.Second*time.Duration(expiry))
}
