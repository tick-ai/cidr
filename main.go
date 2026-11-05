// Command cidr does exact arithmetic on IPv4 and IPv6 networks: info,
// contains, split, merge, exclude and overlaps.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	version       = "0.1.0"
	maxSplit      = 1 << 16
	maxStdinNets  = 5000
	maxOverlapSet = 100000
)

const usageText = `usage: cidr <command> [arguments] [--json]

Exact arithmetic on IPv4 and IPv6 networks.

commands:
  info <network>                 describe a network
  contains <network> <item>...   is every item inside the network? (exit 1 if not)
  split <network> <new length>   list the subnets of the new length
  merge                          smallest set of prefixes covering the networks on stdin
  exclude <network> <network>... what is left of the first network
  overlaps                       report every overlapping pair among the networks on stdin

option:
  --json                         print one JSON object instead of the plain form

  cidr --help | -h               print this text
  cidr --version                 print the version

exit status: 0 done, 1 false (contains, overlaps), 2 usage error or invalid input
`

// ---------------------------------------------------------------------------
// 128-bit unsigned integers

type u128 struct{ hi, lo uint64 }

func (a u128) cmp(b u128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a u128) or(b u128) u128 { return u128{a.hi | b.hi, a.lo | b.lo} }

func (a u128) and(b u128) u128 { return u128{a.hi & b.hi, a.lo & b.lo} }

func (a u128) isZero() bool { return a.hi == 0 && a.lo == 0 }

func (a u128) add(b u128) u128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, c)
	return u128{hi, lo}
}

func (a u128) add1() u128 { return a.add(u128{0, 1}) }

func (a u128) sub1() u128 {
	lo, b := bits.Sub64(a.lo, 1, 0)
	hi, _ := bits.Sub64(a.hi, 0, b)
	return u128{hi, lo}
}

// hostmask returns a value whose low h bits are ones.
func hostmask(h int) u128 {
	var m u128
	switch {
	case h <= 0:
	case h >= 64:
		m.lo = ^uint64(0)
	default:
		m.lo = uint64(1)<<uint(h) - 1
	}
	if h > 64 {
		m.hi = uint64(1)<<uint(h-64) - 1
		if h >= 128 {
			m.hi = ^uint64(0)
		}
	}
	return m
}

// trailingZeros counts the zero bits at the low end of a, at most width.
func trailingZeros(a u128, width int) int {
	t := width
	switch {
	case a.lo != 0:
		t = bits.TrailingZeros64(a.lo)
	case a.hi != 0:
		t = 64 + bits.TrailingZeros64(a.hi)
	}
	if t > width {
		t = width
	}
	return t
}

// ---------------------------------------------------------------------------
// Networks

// network is a prefix of family v (4 or 6). first is its address, for IPv4 in
// the low 32 bits. addr is true when it was written without a length.
type network struct {
	v     int
	first u128
	bits  int
	addr  bool
}

func (n network) width() int {
	if n.v == 4 {
		return 32
	}
	return 128
}

func (n network) hostBits() int { return n.width() - n.bits }

func (n network) last() u128 { return n.first.or(hostmask(n.hostBits())) }

func (n network) prefixString() string {
	return addrString(n.v, n.first) + "/" + strconv.Itoa(n.bits)
}

// itemString is the prefix, or the bare address for an item written as one.
func (n network) itemString() string {
	if n.addr {
		return addrString(n.v, n.first)
	}
	return n.prefixString()
}

func (n network) size() *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(n.hostBits()))
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// parseDec reads one to three ASCII digits without a leading zero, at most max.
func parseDec(s string, max int) (int, bool) {
	if len(s) == 0 || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int(s[i]-'0')
	}
	return v, v <= max
}

func parseIPv4(s string) (uint32, bool) {
	f := strings.Split(s, ".")
	if len(f) != 4 {
		return 0, false
	}
	var v uint32
	for _, p := range f {
		x, ok := parseDec(p, 255)
		if !ok {
			return 0, false
		}
		v = v<<8 | uint32(x)
	}
	return v, true
}

// parseGroups reads colon separated groups; the last may be a dotted IPv4
// address (counted as two groups) when dotted is true.
func parseGroups(part string, dotted bool) ([]uint16, bool) {
	if part == "" {
		return nil, true
	}
	fields := strings.Split(part, ":")
	var out []uint16
	for i, f := range fields {
		if dotted && i == len(fields)-1 && strings.Contains(f, ".") {
			v, ok := parseIPv4(f)
			if !ok {
				return nil, false
			}
			out = append(out, uint16(v>>16), uint16(v))
			continue
		}
		if len(f) == 0 || len(f) > 4 {
			return nil, false
		}
		var g uint16
		for j := 0; j < len(f); j++ {
			c := f[j]
			if !isHex(c) {
				return nil, false
			}
			var d byte
			switch {
			case c <= '9':
				d = c - '0'
			case c >= 'a':
				d = c - 'a' + 10
			default:
				d = c - 'A' + 10
			}
			g = g<<4 | uint16(d)
		}
		out = append(out, g)
	}
	return out, true
}

func parseIPv6(s string) (u128, bool) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isHex(c) && c != ':' && c != '.' {
			return u128{}, false
		}
	}
	var g [8]uint16
	if i := strings.Index(s, "::"); i >= 0 {
		l, ok := parseGroups(s[:i], false)
		if !ok {
			return u128{}, false
		}
		r, ok := parseGroups(s[i+2:], true)
		if !ok || len(l)+len(r) > 7 {
			return u128{}, false
		}
		copy(g[:], l)
		copy(g[8-len(r):], r)
	} else {
		a, ok := parseGroups(s, true)
		if !ok || len(a) != 8 {
			return u128{}, false
		}
		copy(g[:], a)
	}
	var a u128
	for i := 0; i < 4; i++ {
		a.hi = a.hi<<16 | uint64(g[i])
		a.lo = a.lo<<16 | uint64(g[4+i])
	}
	return a, true
}

// parseNetwork reads an address or a prefix. Host bits must be zero.
func parseNetwork(s string) (network, bool) {
	ap, lp, hasLen := strings.Cut(s, "/")
	var n network
	if strings.Contains(ap, ":") {
		a, ok := parseIPv6(ap)
		if !ok {
			return n, false
		}
		n = network{v: 6, first: a, bits: 128, addr: true}
	} else {
		a, ok := parseIPv4(ap)
		if !ok {
			return n, false
		}
		n = network{v: 4, first: u128{0, uint64(a)}, bits: 32, addr: true}
	}
	if hasLen {
		l, ok := parseDec(lp, n.width())
		if !ok {
			return n, false
		}
		n.bits, n.addr = l, false
	}
	if !n.first.and(hostmask(n.hostBits())).isZero() {
		return n, false
	}
	return n, true
}

func addrString(v int, a u128) string {
	if v == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", byte(a.lo>>24), byte(a.lo>>16), byte(a.lo>>8), byte(a.lo))
	}
	var g [8]uint16
	for i := 0; i < 4; i++ {
		g[i] = uint16(a.hi >> uint(48-16*i))
		g[4+i] = uint16(a.lo >> uint(48-16*i))
	}
	// longest run of two or more zero groups, the first on a tie
	bestAt, bestLen := -1, 1
	for i := 0; i < 8; {
		if g[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && g[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestAt, bestLen = i, j-i
		}
		i = j
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if i == bestAt {
			sb.WriteString("::")
			i += bestLen - 1
			continue
		}
		if i > 0 && i != bestAt+bestLen {
			sb.WriteByte(':')
		}
		sb.WriteString(strconv.FormatUint(uint64(g[i]), 16))
	}
	return sb.String()
}

// rangePrefixes returns the smallest sorted list of prefixes covering lo..hi.
func rangePrefixes(v int, lo, hi u128) []network {
	w := 32
	if v == 6 {
		w = 128
	}
	var out []network
	for {
		h := trailingZeros(lo, w)
		for h > 0 && lo.or(hostmask(h)).cmp(hi) > 0 {
			h--
		}
		last := lo.or(hostmask(h))
		out = append(out, network{v: v, first: lo, bits: w - h})
		if last.cmp(hi) == 0 {
			return out
		}
		lo = last.add1()
	}
}

func maxAddr(v int) u128 {
	if v == 4 {
		return u128{0, 1<<32 - 1}
	}
	return u128{^uint64(0), ^uint64(0)}
}

// ---------------------------------------------------------------------------
// Command line

func fail(format string, a ...any) error { return fmt.Errorf(format, a...) }

func main() {
	out, code, err := run(os.Args[1:], os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cidr: %v\n", err)
		os.Exit(2)
	}
	if _, werr := io.WriteString(os.Stdout, out); werr != nil {
		os.Exit(2)
	}
	os.Exit(code)
}

// run executes one command line. It returns what to print on stdout and the
// exit status; on an error nothing is printed on stdout.
func run(args []string, stdin io.Reader) (string, int, error) {
	if len(args) == 1 {
		switch args[0] {
		case "--help", "-h":
			return usageText, 0, nil
		case "--version":
			return "cidr " + version + "\n", 0, nil
		}
	}
	var pos []string
	asJSON := false
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			if a == "--json" {
				asJSON = true
				continue
			}
			return "", 0, fail("unknown option \"%s\" (see cidr --help)", a)
		}
		pos = append(pos, a)
	}
	if len(pos) == 0 {
		return "", 0, fail("no command (usage: cidr <command> [arguments] [--json]; see cidr --help)")
	}
	cmd, rest := pos[0], pos[1:]
	need := func(ok bool, what string) error {
		if ok {
			return nil
		}
		return fail("wrong number of arguments for %s: expected %s", cmd, what)
	}
	var err error
	switch cmd {
	case "info":
		if err = need(len(rest) == 1, "1 network"); err == nil {
			return cmdInfo(rest[0], asJSON)
		}
	case "contains":
		if err = need(len(rest) >= 2, "a network and at least 1 item"); err == nil {
			return cmdContains(rest, asJSON)
		}
	case "split":
		if err = need(len(rest) == 2, "a network and a new length"); err == nil {
			return cmdSplit(rest[0], rest[1], asJSON)
		}
	case "merge":
		if err = need(len(rest) == 0, "none"); err == nil {
			return cmdMerge(stdin, asJSON)
		}
	case "exclude":
		if err = need(len(rest) >= 2, "a network and at least 1 network to remove"); err == nil {
			return cmdExclude(rest, asJSON)
		}
	case "overlaps":
		if err = need(len(rest) == 0, "none"); err == nil {
			return cmdOverlaps(stdin, asJSON)
		}
	default:
		err = fail("unknown command \"%s\" (see cidr --help)", cmd)
	}
	return "", 0, err
}

// parseArgs parses command line networks, then checks that they share a family.
func parseArgs(args []string) ([]network, error) {
	nets := make([]network, len(args))
	for i, a := range args {
		n, ok := parseNetwork(a)
		if !ok {
			return nil, fail("invalid network \"%s\"", a)
		}
		nets[i] = n
	}
	for i := 1; i < len(nets); i++ {
		if nets[i].v != nets[0].v {
			return nil, fail("mixed IPv4 and IPv6: \"%s\" and \"%s\"", args[0], args[i])
		}
	}
	return nets, nil
}

func jsonLine(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

func prefixList(nets []network) []string {
	out := make([]string, len(nets))
	for i, n := range nets {
		out[i] = n.prefixString()
	}
	return out
}

func plainLines(lines []string) string {
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// info

func cmdInfo(arg string, asJSON bool) (string, int, error) {
	nets, err := parseArgs([]string{arg})
	if err != nil {
		return "", 0, err
	}
	n := nets[0]
	type info struct {
		Prefix   string `json:"prefix"`
		Version  int    `json:"version"`
		Length   int    `json:"length"`
		First    string `json:"first"`
		Last     string `json:"last"`
		Size     string `json:"size"`
		Netmask  string `json:"netmask,omitempty"`
		Wildcard string `json:"wildcard,omitempty"`
	}
	r := info{
		Prefix:  n.prefixString(),
		Version: n.v,
		Length:  n.bits,
		First:   addrString(n.v, n.first),
		Last:    addrString(n.v, n.last()),
		Size:    n.size().String(),
	}
	if n.v == 4 {
		wild := hostmask(n.hostBits())
		mask := u128{0, ^wild.lo & 0xffffffff}
		r.Netmask = addrString(4, mask)
		r.Wildcard = addrString(4, wild)
	}
	if asJSON {
		return jsonLine(r), 0, nil
	}
	lines := []string{
		"prefix: " + r.Prefix,
		"version: " + strconv.Itoa(r.Version),
		"length: " + strconv.Itoa(r.Length),
		"first: " + r.First,
		"last: " + r.Last,
		"size: " + r.Size,
	}
	if n.v == 4 {
		lines = append(lines, "netmask: "+r.Netmask, "wildcard: "+r.Wildcard)
	}
	return plainLines(lines), 0, nil
}

// ---------------------------------------------------------------------------
// contains

func cmdContains(args []string, asJSON bool) (string, int, error) {
	nets, err := parseArgs(args)
	if err != nil {
		return "", 0, err
	}
	n := nets[0]
	lo, hi := n.first, n.last()
	type result struct {
		Item      string `json:"item"`
		Contained bool   `json:"contained"`
	}
	results := make([]result, 0, len(nets)-1)
	all := true
	for _, it := range nets[1:] {
		in := it.first.cmp(lo) >= 0 && it.last().cmp(hi) <= 0
		all = all && in
		results = append(results, result{it.itemString(), in})
	}
	code := 0
	if !all {
		code = 1
	}
	if asJSON {
		return jsonLine(struct {
			Network string   `json:"network"`
			Version int      `json:"version"`
			Results []result `json:"results"`
			All     bool     `json:"all"`
		}{n.prefixString(), n.v, results, all}), code, nil
	}
	lines := make([]string, len(results))
	for i, r := range results {
		yn := "no"
		if r.Contained {
			yn = "yes"
		}
		lines[i] = r.Item + " " + yn
	}
	return plainLines(lines), code, nil
}

// ---------------------------------------------------------------------------
// split

func cmdSplit(arg, newLen string, asJSON bool) (string, int, error) {
	nets, err := parseArgs([]string{arg})
	if err != nil {
		return "", 0, err
	}
	n := nets[0]
	nl, ok := parseDec(newLen, n.width())
	if !ok {
		return "", 0, fail("invalid new length \"%s\" for %s", newLen, n.prefixString())
	}
	if nl < n.bits {
		return "", 0, fail("new length \"%s\" is smaller than the length of %s", newLen, n.prefixString())
	}
	if nl-n.bits > 16 {
		return "", 0, fail("split of %s into /%d would give more than %d subnets", n.prefixString(), nl, maxSplit)
	}
	count := 1 << uint(nl-n.bits)
	step := hostmask(n.width() - nl).add1()
	prefixes := make([]string, count)
	cur := n.first
	for i := range prefixes {
		prefixes[i] = network{v: n.v, first: cur, bits: nl}.prefixString()
		cur = cur.add(step)
	}
	if asJSON {
		return jsonLine(struct {
			Network  string   `json:"network"`
			Version  int      `json:"version"`
			Length   int      `json:"length"`
			Count    int      `json:"count"`
			Prefixes []string `json:"prefixes"`
		}{n.prefixString(), n.v, nl, count, prefixes}), 0, nil
	}
	return plainLines(prefixes), 0, nil
}

// ---------------------------------------------------------------------------
// standard input

type entry struct {
	line int
	n    network
}

// readNetworks reads standard input as lines of networks. The returned family
// is 0 when there is no network.
func readNetworks(r io.Reader) ([]entry, int, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, fail("cannot read standard input: %v", err)
	}
	text := string(data)
	if text == "" {
		return nil, 0, nil
	}
	lines := strings.Split(text, "\n")
	if strings.HasSuffix(text, "\n") {
		lines = lines[:len(lines)-1]
	}
	var out []entry
	fam := 0
	for i, raw := range lines {
		line := strings.Trim(raw, " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		n, ok := parseNetwork(line)
		if !ok {
			return nil, 0, fail("line %d: invalid network \"%s\"", i+1, line)
		}
		if fam == 0 {
			fam = n.v
		} else if n.v != fam {
			return nil, 0, fail("line %d: mixed IPv4 and IPv6 (line %d is IPv%d, \"%s\" is IPv%d)", i+1, out[0].line, fam, line, n.v)
		}
		if len(out) >= maxStdinNets {
			return nil, 0, fail("line %d: more than %d networks on standard input", i+1, maxStdinNets)
		}
		out = append(out, entry{i + 1, n})
	}
	return out, fam, nil
}

func versionValue(fam int) any {
	if fam == 0 {
		return nil
	}
	return fam
}

// ---------------------------------------------------------------------------
// merge

func cmdMerge(stdin io.Reader, asJSON bool) (string, int, error) {
	es, fam, err := readNetworks(stdin)
	if err != nil {
		return "", 0, err
	}
	nets := make([]network, len(es))
	for i, e := range es {
		nets[i] = e.n
	}
	sort.Slice(nets, func(i, j int) bool { return nets[i].first.cmp(nets[j].first) < 0 })
	res := []network{}
	if len(nets) > 0 {
		top := maxAddr(fam)
		lo, hi := nets[0].first, nets[0].last()
		for _, n := range nets[1:] {
			if hi.cmp(top) != 0 && n.first.cmp(hi.add1()) <= 0 {
				if l := n.last(); l.cmp(hi) > 0 {
					hi = l
				}
				continue
			}
			if hi.cmp(top) == 0 {
				continue // everything above is already covered
			}
			res = append(res, rangePrefixes(fam, lo, hi)...)
			lo, hi = n.first, n.last()
		}
		res = append(res, rangePrefixes(fam, lo, hi)...)
	}
	prefixes := prefixList(res)
	if asJSON {
		return jsonLine(struct {
			Version  any      `json:"version"`
			Count    int      `json:"count"`
			Prefixes []string `json:"prefixes"`
		}{versionValue(fam), len(prefixes), prefixes}), 0, nil
	}
	return plainLines(prefixes), 0, nil
}

// ---------------------------------------------------------------------------
// exclude

func cmdExclude(args []string, asJSON bool) (string, int, error) {
	nets, err := parseArgs(args)
	if err != nil {
		return "", 0, err
	}
	n := nets[0]
	rem := append([]network(nil), nets[1:]...)
	sort.Slice(rem, func(i, j int) bool { return rem[i].first.cmp(rem[j].first) < 0 })
	lo, hi := n.first, n.last()
	res := []network{}
	cur := lo
	done := false
	for _, r := range rem {
		if r.first.cmp(hi) > 0 {
			break
		}
		if r.last().cmp(cur) < 0 {
			continue
		}
		if r.first.cmp(cur) > 0 {
			res = append(res, rangePrefixes(n.v, cur, r.first.sub1())...)
		}
		if r.last().cmp(hi) >= 0 {
			done = true
			break
		}
		cur = r.last().add1()
	}
	if !done {
		res = append(res, rangePrefixes(n.v, cur, hi)...)
	}
	prefixes := prefixList(res)
	if asJSON {
		return jsonLine(struct {
			Network  string   `json:"network"`
			Version  int      `json:"version"`
			Count    int      `json:"count"`
			Prefixes []string `json:"prefixes"`
		}{n.prefixString(), n.v, len(prefixes), prefixes}), 0, nil
	}
	return plainLines(prefixes), 0, nil
}

// ---------------------------------------------------------------------------
// overlaps

func cmdOverlaps(stdin io.Reader, asJSON bool) (string, int, error) {
	es, fam, err := readNetworks(stdin)
	if err != nil {
		return "", 0, err
	}
	type end struct {
		Line   int    `json:"line"`
		Prefix string `json:"prefix"`
	}
	type pair struct {
		A        end    `json:"a"`
		B        end    `json:"b"`
		Relation string `json:"relation"`
	}
	pairs := []pair{}
	lasts := make([]u128, len(es))
	strs := make([]string, len(es))
	for i, e := range es {
		lasts[i] = e.n.last()
		strs[i] = e.n.prefixString()
	}
	for i, a := range es {
		for j := i + 1; j < len(es); j++ {
			b := es[j]
			if a.n.first.cmp(lasts[j]) > 0 || b.n.first.cmp(lasts[i]) > 0 {
				continue
			}
			rel := "contains"
			switch {
			case a.n.bits == b.n.bits:
				rel = "equals"
			case a.n.bits > b.n.bits:
				rel = "within"
			}
			if len(pairs) >= maxOverlapSet {
				return "", 0, fail("more than %d overlapping pairs", maxOverlapSet)
			}
			pairs = append(pairs, pair{end{a.line, strs[i]}, end{b.line, strs[j]}, rel})
		}
	}
	code := 0
	if len(pairs) > 0 {
		code = 1
	}
	if asJSON {
		return jsonLine(struct {
			Version any    `json:"version"`
			Count   int    `json:"count"`
			Pairs   []pair `json:"pairs"`
		}{versionValue(fam), len(pairs), pairs}), code, nil
	}
	var sb strings.Builder
	for _, p := range pairs {
		fmt.Fprintf(&sb, "%d: %s %s %d: %s\n", p.A.Line, p.A.Prefix, p.Relation, p.B.Line, p.B.Prefix)
	}
	return sb.String(), code, nil
}
