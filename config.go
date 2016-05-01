package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/armon/go-radix"
	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/miekg/dns"
)

type config struct {
	global      *entry // default
	disabled    *entry // empty entry as disabled reference
	entries     *radix.Tree
	allFilters  filterSet
	allBackends backendSet
}

type entry struct {
	backends []*backend
	filters  []filter
	records  map[uint32][]dns.RR
}

func (e *entry) resovleReq(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	key := uint32(q.Qclass)<<16 | uint32(q.Qtype)
	if rr := e.records[key]; rr != nil {
		var resp = new(dns.Msg)
		resp.Question = req.Question
		resp.Answer = rr
		resp.Id = req.Id
		resp.Response = true
		return resp
	} else {
		return nil
	}
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
	defaultLabel = "default"
)

// Parse IPv4 address (d.d.d.d).
func parseIPv4(s string) uint32 {
	var a uint32
	var m byte
	for _, c := range []byte(s) {
		if c >= '0' && c <= '9' { // number
			m = m*10 + c - '0'
		} else if c == '.' {
			a, m = (a<<8)|uint32(m), 0
		} else { // exception
			return 0
		}
	}
	return (a << 8) | uint32(m)
}

type prefilter_descr struct {
	Disabled []string
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
	Prefilters *prefilter_descr
	Backends   map[string][]string
	Filters    map[string]*filter_descr
	Domains    map[string]*domain_descr
	Zones      []string
}

func parseBackend(s string) *backend {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	be := &backend{
		net:  u.Scheme,
		addr: u.Host,
	}
	_, _, err = net.SplitHostPort(u.Host)
	if ae, y := err.(*net.AddrError); y {
		if strings.Contains(ae.Err, "port") {
			be.addr += ":53"
		} else {
			panic(err)
		}
	}
	be.url = fmt.Sprintf("%s://%s", be.net, be.addr)
	return be
}

func parseDenyFilters(arr []string) filter {
	var f droppingV4Filter
	f.rules = make(map[uint32]bool)
	var callback = func(item string) {
		ip_num := parseIPv4(item)
		if ip_num == 0 {
			panic("bad filter " + item)
		}
		f.rules[ip_num] = true
	}
	for _, a := range arr {
		if strings.HasPrefix(a, "@") {
			addItemsFromFile(a[1:], callback)
		} else {
			callback(a)
		}
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
		if ip_a*ip_b == 0 {
			panic("bad filter " + a)
		}
		f.rules[ip_a] = ip_b
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

func (c *config) parseZones(t *radix.Tree, zones []string) {
	for _, str := range zones {
		str = strings.TrimSpace(str)
		rr, err := dns.NewRR(str)
		if err != nil {
			panic(err)
		}
		rrname := rr.Header().Name
		rrname = reverseCharacters(rrname)[1:]
		nkey, en, y := t.LongestPrefix(rrname)
		var de *entry
		if !y || nkey != rrname {
			de = new(entry)
			t.Insert(rrname, de)
		} else {
			de = en.(*entry)
		}
		rrMap := de.records
		if rrMap == nil {
			rrMap = make(map[uint32][]dns.RR)
			de.records = rrMap
		}
		h := rr.Header()
		key := uint32(h.Class)<<16 | uint32(h.Rrtype)
		rrMap[key] = append(rrMap[key], rr)
	}
}

func isAlphabetOrNumber(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

func addItemsFromFile(name string, callback func(string)) {
	fr, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	defer fr.Close()
	rd := bufio.NewReader(fr)
	for {
		line_b, _, err := rd.ReadLine()
		if len(line_b) > 0 {
			line := strings.TrimSpace(string(line_b))
			if isAlphabetOrNumber(line[0]) {
				callback(line)
			}
		}
		if err != nil {
			break
		}
	}
}

func parsePrefilters(f *prefilter_descr, tree *radix.Tree, e *entry) {
	var callback = func(item string) {
		tree.Insert(reverseCharacters(item), e)
	}
	for _, name := range f.Disabled {
		if len(name) > 1 {
			// include file
			if name[0] == '@' {
				addItemsFromFile(name[1:], callback)
			} else { // normal entry
				tree.Insert(reverseCharacters(name), e)
			}
		}
	}
}

func initialConfig(file string, conf *config) (err error) {
	//	defer func() {
	//		if e := recover(); e != nil {
	//			err = fmt.Errorf("%T:%v", e, e)
	//		}
	//	}()

	content, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	var des config_descr
	err = hcl.Unmarshal(content, &des)
	if err != nil {
		return
	}

	// parse backends
	var allBackends = make(backendSet)
	for k, v := range des.Backends {
		var bs []*backend
		for _, a := range v {
			bs = append(bs, parseBackend(a))
		}
		allBackends[k] = bs
	}

	// parse filters
	var allFilters = make(filterSet)
	for k, v := range des.Filters {
		parseFilter(allFilters, k, v)
	}

	// set fields of config instance
	conf.allFilters = allFilters
	conf.allBackends = allBackends
	conf.global = &entry{
		backends: allBackends[defaultLabel],
		filters:  allFilters[defaultLabel],
	}

	// parse domains
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
	// parse prefilter
	disabled := &entry{}
	conf.disabled = disabled
	parsePrefilters(des.Prefilters, entries, disabled)
	// parse zones
	conf.parseZones(entries, des.Zones)

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
