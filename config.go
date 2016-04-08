package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/armon/go-radix"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/printer"
)

type config struct {
	global      *entry
	entries     *radix.Tree
	allFilters  filterSet
	allBackends backendSet
}

type entry struct {
	backends []*backend
	filters  []filter
}

func reverseCharacters(src string) string {
	a := []byte(src)
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[j], a[i] = a[i], a[j]
	}
	return string(a)
}

func (c *config) findEntry(name string) *entry {
	name = reverseCharacters(name)
	if name[0] == '.' {
		name = name[1:]
	}
	_, val, found := c.entries.LongestPrefix(name)
	if found {
		return val.(*entry)
	} else {
		return c.global
	}
}

const (
	_IPv4len      = 4
	big          = 0xFFFFFF
	defaultLabel = "default"
)

// Parse IPv4 address (d.d.d.d).
func parseIPv4(s string) []byte {
	var p [_IPv4len]byte
	i := 0
	for j := 0; j < _IPv4len; j++ {
		if i >= len(s) {
			// Missing octets.
			return nil
		}
		if j > 0 {
			if s[i] != '.' {
				return nil
			}
			i++
		}
		var (
			n  int
			ok bool
		)
		n, i, ok = dtoi(s, i)
		if !ok || n > 0xFF {
			return nil
		}
		p[j] = byte(n)
	}
	if i != len(s) {
		return nil
	}
	return p[:]
}

// Decimal to integer starting at &s[i0].
// Returns number, new offset, success.
func dtoi(s string, i0 int) (n int, i int, ok bool) {
	n = 0
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	for i = i0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			if neg {
				return -big, i + 1, false
			}
			return big, i, false
		}
	}
	if i == i0 {
		return 0, i, false
	}
	if neg {
		n = -n
		i++
	}
	return n, i, true
}

type filter_descr struct {
	Drop    []string
	Replace []string
}

type domain_descr struct {
	Backends []string
	Filters  []string
}

type config_descr struct {
	Backends map[string][]string
	Filters  map[string]*filter_descr
	Domains  map[string]*domain_descr
}

func parseBackend(s string) *backend {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	backend := &backend{
		net:  u.Scheme,
		addr: u.Host,
	}
	_, _, err = net.SplitHostPort(u.Host)
	if ae, y := err.(*net.AddrError); y {
		if strings.Contains(ae.Err, "port") {
			backend.addr += ":53"
		} else {
			panic(err)
		}
	}
	return backend
}

func parseDenyFilters(arr []string) filter {
	var f droppingV4Filter
	f.rules = make(map[uint32]bool)
	for _, a := range arr {
		ip_b := parseIPv4(a)
		if ip_b == nil {
			panic("bad filter " + a)
		}
		ip_n := binary.BigEndian.Uint32(ip_b)
		f.rules[ip_n] = true
	}
	return &f
}

func parseReplaceFilter(arr []string) filter {
	var f replacementV4Filter
	f.rules = make(map[uint32]uint32)
	for _, a := range arr {
		parr := strings.Split(a, "/")
		if len(parr) != 2 {
			panic("bad filter " + a)
		}
		ip_a := parseIPv4(parr[0])
		ip_b := parseIPv4(parr[1])
		if ip_a == nil || ip_b == nil {
			panic("bad filter " + a)
		}
		ip_an := binary.BigEndian.Uint32(ip_a)
		ip_bn := binary.BigEndian.Uint32(ip_b)
		f.rules[ip_an] = ip_bn
	}
	return &f
}

func parseFilter(fs filterSet, label string, f *filter_descr) {
	filters := fs[label]
	if f.Drop != nil {
		filters = append(filters, parseDenyFilters(f.Drop))
	}
	if f.Replace != nil {
		filters = append(filters, parseReplaceFilter(f.Replace))
	}
	fs[label] = filters
}

func (c *config) parseDomain(d *domain_descr) *entry {
	var entry = new(entry)
	for _, str := range d.Backends {
		bs := c.allBackends[str]
		if bs == nil {
			panic("bad backend reference")
		}
		entry.backends = append(entry.backends, bs...)
	}
	for _, str := range d.Filters {
		f := c.allFilters[str]
		if f == nil {
			panic("bad filter reference")
		}
		entry.filters = append(entry.filters, f...)
	}
	return entry
}

func initialConfig(file string, conf *config) (err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%T:%v", e, e)
		}
	}()

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	var des config_descr
	err = hcl.Unmarshal(content, &des)
	if err != nil {
		return
	}

	var allBackends = make(backendSet)
	for k, v := range des.Backends {
		var bs []*backend
		for _, a := range v {
			bs = append(bs, parseBackend(a))
		}
		allBackends[k] = bs
	}

	var allFilters = make(filterSet)
	for k, v := range des.Filters {
		parseFilter(allFilters, k, v)
	}

	// set config fields
	conf.allFilters = allFilters
	conf.allBackends = allBackends
	conf.global = &entry{
		backends: allBackends[defaultLabel],
		filters:  allFilters[defaultLabel],
	}

	var entries = radix.New()
	for k, v := range des.Domains {
		entry := conf.parseDomain(v)
		if strings.Contains(k, ",") {
			for _, nk := range strings.Split(k, ",") {
				nk = strings.TrimSpace(nk)
				nk = reverseCharacters(nk)
				entries.Insert(nk, entry)
			}
		} else {
			k = reverseCharacters(k)
			entries.Insert(k, entry)
		}
		// inherit global
		if entry.backends == nil {
			entry.backends = conf.global.backends
		}
		if entry.filters == nil {
			entry.filters = conf.global.filters
		}
	}

	conf.entries = entries
	return
}

func formatConfig(file string) error {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	tree, err := hcl.ParseBytes(content)
	if err != nil {
		return err
	}
	fw, err := os.OpenFile(file, os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer fw.Close()
	defer fmt.Fprintln(fw, "")
	printer.DefaultConfig.SpacesWidth = 4
	return printer.Fprint(fw, tree.Node)
}
