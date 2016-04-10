package main

import (
	"encoding/binary"
	"log"

	"github.com/miekg/dns"
)

type filterSet map[string][]filter

type filter interface {
	filter(answers []dns.RR, msg *dns.Msg) []dns.RR
}

type droppingV4Filter struct {
	rules map[uint32]bool
}

func (f *droppingV4Filter) filter(answers []dns.RR, msg *dns.Msg) []dns.RR {
	var a *dns.A
	for _, rr := range answers {
		// only accept A
		if arr, y := rr.(*dns.A); y {
			ip := binary.BigEndian.Uint32(arr.A.To4())
			if f.rules[ip] {
				log.Println("\tdrop", arr)
				return nil
			} else {
				a = arr
			}
		}
	}
	// passed the test that based on fixed rules
	if len(answers) == 1 && a != nil && len(msg.Extra) == 0 {
		// only got one answer that one is little dubious
		log.Println("\tshould verify", a.Hdr.Name, a.A)
		a.Hdr.Ttl = 2
	}
	return answers
}

// only drop one RR
func (f *droppingV4Filter) filter1(answers []dns.RR) []dns.RR {
	max := len(answers) - 1
	for i := 0; i <= max; {
		rr := answers[i]
		// only accept A
		if arr, y := rr.(*dns.A); y {
			ip := binary.BigEndian.Uint32(arr.A.To4())
			if f.rules[ip] {
				log.Println("\tdrop", arr)
				// swap i with tail
				if i < max {
					answers[i] = answers[max]
				}
				max--
				continue
			}
		}
		i++
	}
	return answers[:max+1]
}

type replacementV4Filter struct {
	rules map[uint32]uint32
}

func (f *replacementV4Filter) filter(answers []dns.RR, msg *dns.Msg) []dns.RR {
	for _, rr := range answers {
		if arr, y := rr.(*dns.A); y {
			ip := binary.BigEndian.Uint32(arr.A.To4())
			if repl, y := f.rules[ip]; y {
				log.Println("\treplace", arr)
				binary.BigEndian.PutUint32(arr.A, repl)
			}
		}
	}
	return answers
}
