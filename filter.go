package main

import (
	"encoding/binary"
	"log"

	"github.com/miekg/dns"
)

type filterSet map[string][]filter

type filter interface {
	filter(answers []dns.RR) []dns.RR
}

type droppingV4Filter struct {
	rules map[uint32]bool
}

func (f *droppingV4Filter) filter(answers []dns.RR) []dns.RR {
	for _, rr := range answers {
		// only accept A
		if arr, y := rr.(*dns.A); y {
			ip := binary.BigEndian.Uint32(arr.A.To4())
			if f.rules[ip] {
				log.Println("\tdrop", arr)
				return nil
			}
		}
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

func (f *replacementV4Filter) filter(answers []dns.RR) []dns.RR {
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
