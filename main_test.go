package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cidr-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "cidr")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// cidr runs the built binary as a child process in a folder of its own.
func cidr(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running cidr %q: %v", args, err)
	}
	return so.String(), se.String(), code
}

// ok checks the output and exit status of a run.
func ok(t *testing.T, stdin string, wantOut string, wantCode int, args ...string) {
	t.Helper()
	out, errOut, code := cidr(t, stdin, args...)
	if out != wantOut || code != wantCode {
		t.Errorf("cidr %q: got code %d, stdout %q (stderr %q); want code %d, stdout %q", args, code, out, errOut, wantCode, wantOut)
	}
	if code == 2 && !strings.HasPrefix(errOut, "cidr: ") {
		t.Errorf("cidr %q: stderr %q does not start with \"cidr: \"", args, errOut)
	}
}

// bad checks an exit status 2 with empty stdout and a cidr: message that holds
// every word of want.
func bad(t *testing.T, stdin string, want []string, args ...string) {
	t.Helper()
	out, errOut, code := cidr(t, stdin, args...)
	if code != 2 || out != "" {
		t.Errorf("cidr %q: got code %d, stdout %q; want code 2 and no stdout", args, code, out)
	}
	if !strings.HasPrefix(errOut, "cidr: ") {
		t.Errorf("cidr %q: stderr %q does not start with \"cidr: \"", args, errOut)
	}
	for _, w := range want {
		if !strings.Contains(errOut, w) {
			t.Errorf("cidr %q: stderr %q lacks %q", args, errOut, w)
		}
	}
}

func lines(s ...string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.Join(s, "\n") + "\n"
}

func TestHelpAndVersion(t *testing.T) {
	for _, a := range []string{"--help", "-h"} {
		out, _, code := cidr(t, "", a)
		if code != 0 || !strings.HasPrefix(out, "usage: cidr") {
			t.Errorf("%s: code %d, out %q", a, code, out)
		}
		for _, c := range []string{"info", "contains", "split", "merge", "exclude", "overlaps"} {
			if !strings.Contains(out, c) {
				t.Errorf("%s: usage does not name %s", a, c)
			}
		}
	}
	ok(t, "", "cidr 0.1.0\n", 0, "--version")
	// anywhere else they are unknown options
	for _, args := range [][]string{
		{"--help", "--json"}, {"info", "--help"}, {"-h", "info"}, {"--version", "info", "10.0.0.0/8"},
		{"--json", "--version"}, {"info", "-h", "10.0.0.0/8"},
	} {
		bad(t, "", nil, args...)
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"--json"},
		{"--json", "--json"},
		{""},
		{"frobnicate"},
		{"INFO", "10.0.0.0/8"},
		{"-"},
		{"--"},
		{"--json=1", "info", "10.0.0.0/8"},
		{"--color", "info", "10.0.0.0/8"},
		{"-x"},
		{"info"},
		{"info", "10.0.0.0/8", "10.0.0.0/8"},
		{"contains"},
		{"contains", "10.0.0.0/8"},
		{"split"},
		{"split", "10.0.0.0/8"},
		{"split", "10.0.0.0/8", "16", "17"},
		{"merge", "10.0.0.0/8"},
		{"exclude"},
		{"exclude", "10.0.0.0/8"},
		{"overlaps", "10.0.0.0/8"},
		{"info", "--", "10.0.0.0/8"},
		{"info", "-", "10.0.0.0/8"},
	}
	for _, args := range cases {
		bad(t, "10.0.0.0/8\n", nil, args...)
	}
}

func TestIPv4Forms(t *testing.T) {
	good := map[string]string{
		"0.0.0.0":         "0.0.0.0",
		"255.255.255.255": "255.255.255.255",
		"192.0.2.1":       "192.0.2.1",
		"10.0.0.0":        "10.0.0.0",
	}
	for in, want := range good {
		ok(t, "", lines("prefix: "+want+"/32", "version: 4", "length: 32", "first: "+want, "last: "+want, "size: 1", "netmask: 255.255.255.255", "wildcard: 0.0.0.0"), 0, "info", in)
	}
	for _, in := range []string{
		"", " 10.0.0.0/8", "10.0.0.0/8 ", "10.0.0.0 ", "10.1", "10.0.0", "10.0.0.0.0", "10.0.0.256", "256.0.0.0",
		"010.0.0.0", "10.00.0.0", "10.0.0.01", "0x0a.0.0.0", "1e1.0.0.0", "10.0.0.-1", "10..0.0", ".10.0.0.0", "10.0.0.0.",
		"+1.0.0.0", "1000.0.0.0", "10.0.0.0/08", "10.0.0.0/8/8", "10.0.0.0/", "/8", "10.0.0.0/33", "10.0.0.0/-1",
		"10.0.0.0/+8", "10.0.0.0/255.0.0.0", "10.0.0.0/0008", "10.0.0.0/ 8", "10.0.0.0/8 ", "10.0.0.1/8", "10.0.0.1/31",
		"10.0.0.0/x", "10.0.0.0/１", "1.2.3.4:80", "[10.0.0.0]/8", "10.0.0.0\n", "10.0.0.0#x",
	} {
		bad(t, "", []string{in}, "info", in)
	}
	ok(t, "", lines("prefix: 10.0.0.1/32", "version: 4", "length: 32", "first: 10.0.0.1", "last: 10.0.0.1", "size: 1", "netmask: 255.255.255.255", "wildcard: 0.0.0.0"), 0, "info", "10.0.0.1/32")
	ok(t, "", lines("prefix: 0.0.0.0/0", "version: 4", "length: 0", "first: 0.0.0.0", "last: 255.255.255.255", "size: 4294967296", "netmask: 0.0.0.0", "wildcard: 255.255.255.255"), 0, "info", "0.0.0.0/0")
}

func TestIPv6Forms(t *testing.T) {
	good := [][2]string{
		{"::", "::"},
		{"::1", "::1"},
		{"1::", "1::"},
		{"0:0:0:0:0:0:0:0", "::"},
		{"0000:0000:0000:0000:0000:0000:0000:0001", "::1"},
		{"2001:0DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
		{"1:0:0:2:0:0:0:3", "1:0:0:2::3"},
		{"1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7"},
		{"1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0"},
		{"::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8"},
		{"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
		{"1:0:0:2:3:0:0:4", "1::2:3:0:0:4"},
		{"1:0:0:0:2:0:0:0", "1::2:0:0:0"},
		{"1:2:3:0:0:0:7:8", "1:2:3::7:8"},
		{"0:0:1:0:0:0:0:1", "0:0:1::1"},
		{"ABCD:EF01:2345:6789:ABCD:EF01:2345:6789", "abcd:ef01:2345:6789:abcd:ef01:2345:6789"},
		{"::ffff:192.0.2.1", "::ffff:c000:201"},
		{"::FFFF:192.0.2.1", "::ffff:c000:201"},
		{"64:ff9b::192.0.2.33", "64:ff9b::c000:221"},
		{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
		{"::1.2.3.4", "::102:304"},
		{"::0.0.0.0", "::"},
		{"1::1.2.3.4", "1::102:304"},
		{"0:0:0:0:0:ffff:0.0.0.0", "::ffff:0:0"},
		{"2001:db8::", "2001:db8::"},
		{"fe80::", "fe80::"},
		{"1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:0"},
	}
	for _, c := range good {
		out, errOut, code := cidr(t, "", "info", c[0])
		want := "prefix: " + c[1] + "/128\n"
		if code != 0 || !strings.HasPrefix(out, want) {
			t.Errorf("info %q: code %d, stdout %q, stderr %q; want first line %q", c[0], code, out, errOut, want)
		}
	}
	for _, in := range []string{
		":", ":::", "::::", "1:::2", "1::2::3", ":1::2", "1::2:", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "1:2:3:4:5:6:7",
		"1:2:3:4:5:6:7:8:9", "1:2:3:4::5:6:7:8", "1:2:3:4:5:6:7::8", "12345::", "::12345", "1:2:3:4:5:6:7:fffff",
		"fe80::1%eth0", "fe80::1%", "[::1]", "[::1]/128", "::g", "::1 ", " ::1", "1::2:3:4:5:6:7:8", "::1.2.3", "::1.2.3.4.5",
		"::1.2.3.256", "::01.2.3.4", "::1.2.3.04", "::1.2.3.4:5", "1.2.3.4::", "1.2.3.4::1", "::1.2.3.4:", "1:2:3:4:5:6:7:1.2.3.4",
		"1:2:3:4:5:1.2.3.4", "1:2:3:4:5:6:7.8", "::ffff:1.2.3.4/129", "::/129", "::/-1", "::/00", "::/01", "::/", "1::1/0",
		"2001:db8::1/32", "::1/127", "::ffff:192.0.2.1/96", "ff:ff::/8", "::1/1000", "::%1", "0:0:0:0:0:0:0:0:0", "::x:1", "1::-1",
	} {
		bad(t, "", []string{in}, "info", in)
	}
}

func TestPrefixHostBits(t *testing.T) {
	for _, in := range []string{"10.0.0.1/8", "2001:db8::1/32", "10.128.0.0/8", "::1/0", "255.255.255.255/31", "0.0.0.1/0"} {
		bad(t, "", []string{in}, "info", in)
	}
	for _, in := range []string{"10.0.0.1/32", "10.0.0.0/8", "2001:db8::1/128", "2001:db8::/32", "::/0", "0.0.0.0/0", "10.0.0.254/31", "10.0.0.0/7"} {
		_, _, code := cidr(t, "", "info", in)
		if code != 0 {
			t.Errorf("info %s: code %d", in, code)
		}
	}
}

func TestInfo(t *testing.T) {
	ok(t, "", lines("prefix: 10.0.0.0/8", "version: 4", "length: 8", "first: 10.0.0.0", "last: 10.255.255.255", "size: 16777216", "netmask: 255.0.0.0", "wildcard: 0.255.255.255"), 0, "info", "10.0.0.0/8")
	ok(t, "", lines("prefix: 192.168.1.128/25", "version: 4", "length: 25", "first: 192.168.1.128", "last: 192.168.1.255", "size: 128", "netmask: 255.255.255.128", "wildcard: 0.0.0.127"), 0, "info", "192.168.1.128/25")
	ok(t, "", lines("prefix: 2001:db8::/32", "version: 6", "length: 32", "first: 2001:db8::", "last: 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "size: 79228162514264337593543950336"), 0, "info", "2001:DB8:0::/32")
	ok(t, "", lines("prefix: ::/0", "version: 6", "length: 0", "first: ::", "last: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "size: 340282366920938463463374607431768211456"), 0, "info", "::/0")
	ok(t, "", lines("prefix: ::1/128", "version: 6", "length: 128", "first: ::1", "last: ::1", "size: 1"), 0, "info", "::1")
	ok(t, "", lines("prefix: ::ffff:c000:200/120", "version: 6", "length: 120", "first: ::ffff:c000:200", "last: ::ffff:c000:2ff", "size: 256"), 0, "info", "::ffff:192.0.2.0/120")
	// the size of an IPv6 /0 exactly
	want := new(big.Int).Lsh(big.NewInt(1), 128).String()
	if want != "340282366920938463463374607431768211456" {
		t.Fatal("bad constant")
	}
	out, _, code := cidr(t, "", "info", "::/0")
	if code != 0 || !strings.Contains(out, "size: "+want+"\n") {
		t.Errorf("::/0: %q", out)
	}
	for _, c := range []struct {
		in, size string
	}{{"::/1", "170141183460469231731687303715884105728"}, {"::/64", "18446744073709551616"}, {"::/65", "9223372036854775808"}, {"::/127", "2"}, {"::/63", "36893488147419103232"}} {
		out, _, _ := cidr(t, "", "info", c.in)
		if !strings.Contains(out, "size: "+c.size+"\n") {
			t.Errorf("info %s: %q", c.in, out)
		}
	}
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Fatalf("JSON is not one line: %q", s)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad JSON %q: %v", s, err)
	}
	return m
}

func keys(m map[string]any) string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func TestInfoJSON(t *testing.T) {
	out, _, code := cidr(t, "", "info", "--json", "10.0.0.0/8")
	m := decode(t, out)
	if code != 0 || keys(m) != "first,last,length,netmask,prefix,size,version,wildcard" {
		t.Fatalf("keys %s code %d", keys(m), code)
	}
	if m["prefix"] != "10.0.0.0/8" || m["version"] != float64(4) || m["length"] != float64(8) || m["first"] != "10.0.0.0" ||
		m["last"] != "10.255.255.255" || m["size"] != "16777216" || m["netmask"] != "255.0.0.0" || m["wildcard"] != "0.255.255.255" {
		t.Errorf("wrong values: %v", m)
	}
	out, _, _ = cidr(t, "", "--json", "info", "::/0", "--json")
	m = decode(t, out)
	if keys(m) != "first,last,length,prefix,size,version" || m["size"] != "340282366920938463463374607431768211456" || m["version"] != float64(6) || m["length"] != float64(0) {
		t.Errorf("v6 json: %v", m)
	}
}

func TestContains(t *testing.T) {
	ok(t, "", lines("10.1.2.3 yes", "192.168.0.0/16 no"), 1, "contains", "10.0.0.0/8", "10.1.2.3", "192.168.0.0/16")
	ok(t, "", lines("10.1.0.0/16 yes", "10.1.2.3/32 yes", "10.0.0.0/8 yes", "10.0.0.0 yes", "10.255.255.255 yes", "9.255.255.255 no", "11.0.0.0 no", "0.0.0.0/0 no", "10.0.0.0/7 no"), 1,
		"contains", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.3/32", "10.0.0.0/8", "10.0.0.0", "10.255.255.255", "9.255.255.255", "11.0.0.0", "0.0.0.0/0", "10.0.0.0/7")
	ok(t, "", lines("10.1.0.0/16 yes", "10.1.0.0/16 yes"), 0, "contains", "10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16")
	ok(t, "", lines("2001:db8::1 yes", "2001:db8:1::/48 yes", "::ffff:c000:201 no"), 1, "contains", "2001:db8::/32", "2001:DB8:0:0:0:0:0:1", "2001:db8:1::/48", "::ffff:192.0.2.1")
	ok(t, "", lines("10.0.0.1 yes", "10.0.0.1/32 yes", "10.0.0.2 no"), 1, "contains", "10.0.0.1", "10.0.0.1", "10.0.0.1/32", "10.0.0.2")
	ok(t, "", lines("1.2.3.4 yes", "255.255.255.255/32 yes", "0.0.0.0/0 yes"), 0, "contains", "0.0.0.0/0", "1.2.3.4", "255.255.255.255/32", "0.0.0.0/0")
	ok(t, "", lines("::1 yes"), 0, "contains", "::/0", "::1")
	// the first and the last address
	ok(t, "", lines("10.0.0.0/24 yes", "10.0.1.0 no"), 1, "contains", "10.0.0.0/24", "10.0.0.0/24", "10.0.1.0")
	// mixed families are invalid, not a "no"
	bad(t, "", []string{"mixed"}, "contains", "10.0.0.0/8", "2001:db8::1")
	bad(t, "", []string{"mixed"}, "contains", "2001:db8::/32", "10.0.0.1")
	bad(t, "", []string{"mixed"}, "contains", "10.0.0.0/8", "10.0.0.1", "::ffff:10.0.0.1")
	bad(t, "", []string{"10.0.0.0/08"}, "contains", "10.0.0.0/8", "10.0.0.0/08")
	bad(t, "", []string{"10.0.0.1/8"}, "contains", "10.0.0.1/8", "10.0.0.1")
	bad(t, "", []string{"x"}, "contains", "10.0.0.0/8", "10.0.0.1", "x")

	out, _, code := cidr(t, "", "contains", "10.0.0.0/8", "10.1.2.3", "192.168.0.0/16", "--json")
	m := decode(t, out)
	if code != 1 || keys(m) != "all,network,results,version" || m["network"] != "10.0.0.0/8" || m["version"] != float64(4) || m["all"] != false {
		t.Fatalf("json: %v code %d", m, code)
	}
	res := m["results"].([]any)
	if len(res) != 2 {
		t.Fatalf("results: %v", res)
	}
	r0, r1 := res[0].(map[string]any), res[1].(map[string]any)
	if keys(r0) != "contained,item" || r0["item"] != "10.1.2.3" || r0["contained"] != true || r1["item"] != "192.168.0.0/16" || r1["contained"] != false {
		t.Errorf("results: %v", res)
	}
	out, _, code = cidr(t, "", "--json", "contains", "2001:db8::/32", "2001:db8::1")
	m = decode(t, out)
	if code != 0 || m["network"] != "2001:db8::/32" || m["version"] != float64(6) || m["all"] != true {
		t.Errorf("json v6: %v code %d", m, code)
	}
}

func TestSplit(t *testing.T) {
	ok(t, "", lines("10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"), 0, "split", "10.0.0.0/24", "26")
	ok(t, "", lines("10.0.0.0/24"), 0, "split", "10.0.0.0/24", "24")
	ok(t, "", lines("10.0.0.5/32"), 0, "split", "10.0.0.5", "32")
	ok(t, "", lines("0.0.0.0/1", "128.0.0.0/1"), 0, "split", "0.0.0.0/0", "1")
	ok(t, "", lines("2001:db8::/34", "2001:db8:4000::/34", "2001:db8:8000::/34", "2001:db8:c000::/34"), 0, "split", "2001:db8::/32", "34")
	ok(t, "", lines("::/128"), 0, "split", "::", "128")
	ok(t, "", lines("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), 0, "split", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "128")

	out, _, code := cidr(t, "", "split", "10.0.0.0/8", "24")
	ls := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || len(ls) != 65536 || ls[0] != "10.0.0.0/24" || ls[1] != "10.0.1.0/24" || ls[65535] != "10.255.255.0/24" {
		t.Errorf("split /8 into /24: code %d, %d lines", code, len(ls))
	}
	out, _, code = cidr(t, "", "split", "::/0", "16")
	ls = strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || len(ls) != 65536 || ls[0] != "::/16" || ls[1] != "1::/16" || ls[65535] != "ffff::/16" {
		t.Errorf("split ::/0 into /16: code %d, %d lines, %q", code, len(ls), ls[:2])
	}

	bad(t, "", []string{"65536"}, "split", "10.0.0.0/8", "25")
	bad(t, "", nil, "split", "::/0", "17")
	bad(t, "", nil, "split", "2001:db8::/32", "64")
	bad(t, "", nil, "split", "0.0.0.0/0", "17")
	bad(t, "", nil, "split", "10.0.0.0/24", "23")
	bad(t, "", nil, "split", "10.0.0.0/24", "33")
	bad(t, "", nil, "split", "::/0", "129")
	bad(t, "", nil, "split", "10.0.0.0/24", "")
	bad(t, "", nil, "split", "10.0.0.0/24", "/26")
	bad(t, "", nil, "split", "10.0.0.0/24", "026")
	bad(t, "", nil, "split", "10.0.0.0/24", "+26")
	bad(t, "", nil, "split", "10.0.0.0/24", "-26")
	bad(t, "", nil, "split", "10.0.0.0/24", " 26")
	bad(t, "", nil, "split", "10.0.0.0/24", "26.0")
	bad(t, "", nil, "split", "10.0.0.0/24", "x")
	bad(t, "", []string{"10.0.0.1/24"}, "split", "10.0.0.1/24", "26")

	out, _, code = cidr(t, "", "split", "10.0.0.0/24", "26", "--json")
	m := decode(t, out)
	if code != 0 || keys(m) != "count,length,network,prefixes,version" || m["network"] != "10.0.0.0/24" || m["version"] != float64(4) ||
		m["length"] != float64(26) || m["count"] != float64(4) {
		t.Fatalf("split json: %v", m)
	}
	ps := m["prefixes"].([]any)
	if len(ps) != 4 || ps[0] != "10.0.0.0/26" || ps[3] != "10.0.0.192/26" {
		t.Errorf("prefixes %v", ps)
	}
}

func TestMerge(t *testing.T) {
	ok(t, lines("10.0.0.0/25", "10.0.0.128/25"), lines("10.0.0.0/24"), 0, "merge")
	ok(t, lines("10.0.0.1"), lines("10.0.0.1/32"), 0, "merge")
	ok(t, lines("10.0.0.0/24", "10.0.1.0/24"), lines("10.0.0.0/23"), 0, "merge")
	ok(t, lines("10.0.1.0/24", "10.0.2.0/24"), lines("10.0.1.0/24", "10.0.2.0/24"), 0, "merge")
	ok(t, lines("10.0.0.0/8"), lines("10.0.0.0/8"), 0, "merge")
	ok(t, lines("10.1.0.0/16", "10.0.0.0/8", "10.0.0.0/8", "10.2.3.4"), lines("10.0.0.0/8"), 0, "merge")
	ok(t, lines("10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.0"), lines("10.0.0.0/30"), 0, "merge")
	ok(t, lines("10.0.0.1", "10.0.0.2"), lines("10.0.0.1/32", "10.0.0.2/32"), 0, "merge")
	ok(t, lines("10.0.0.1", "10.0.0.2", "10.0.0.3"), lines("10.0.0.1/32", "10.0.0.2/31"), 0, "merge")
	ok(t, lines("0.0.0.0/1", "128.0.0.0/1"), lines("0.0.0.0/0"), 0, "merge")
	ok(t, lines("255.255.255.255", "255.255.255.254", "0.0.0.0/0"), lines("0.0.0.0/0"), 0, "merge")
	ok(t, lines("128.0.0.0/1", "255.255.255.255"), lines("128.0.0.0/1"), 0, "merge")
	ok(t, lines("::/1", "8000::/1"), lines("::/0"), 0, "merge")
	ok(t, lines("::ffff:10.0.0.0/120", "::ffff:10.0.1.0/120"), lines("::ffff:a00:0/119"), 0, "merge")
	ok(t, lines("2001:db8::/33", "2001:db8:8000::/33", "2001:db9::/32"), lines("2001:db8::/31"), 0, "merge")
	ok(t, lines("2001:DB8::1", "2001:db8:0:0:0:0:0:0"), lines("2001:db8::/127"), 0, "merge")

	// the line rules
	in := "\n  # a comment\n\t10.0.0.0/25\r\n   \n10.0.0.128/25   \n#10.1.0.0/16\n \t \r\n"
	ok(t, in, lines("10.0.0.0/24"), 0, "merge")
	ok(t, "10.0.0.0/24", lines("10.0.0.0/24"), 0, "merge") // no final newline
	ok(t, "10.0.0.0/24\n\n", lines("10.0.0.0/24"), 0, "merge")

	// nothing at all
	for _, in := range []string{"", "\n", "\n\n  \n", "# x\n", "  # x\n\t\n", " \r\n"} {
		ok(t, in, "", 0, "merge")
		ok(t, in, "{\"version\":null,\"count\":0,\"prefixes\":[]}\n", 0, "merge", "--json")
	}

	// invalid lines
	bad(t, "10.0.0.0/8\n10.1.0.0/16 # c\n", []string{"line 2"}, "merge")
	bad(t, "\n\n10.0.0.0/8 10.1.0.0/16\n", []string{"line 3"}, "merge")
	bad(t, "10.0.0.0/8\n\xef\xbb\xbf10.1.0.0/16\n", []string{"line 2"}, "merge")
	bad(t, "# c\n10.0.0.1/8\n", []string{"line 2"}, "merge")
	bad(t, "10.0.0.0/8\n\n#\n10.0.0.0/08\n", []string{"line 4"}, "merge")
	bad(t, "10.0.0.0/8\n10.0.0.0/8,\n", []string{"line 2"}, "merge")
	bad(t, "10.0.0.0/8\n10.0.0.0\x00\n", []string{"line 2"}, "merge")
	bad(t, "10.0.0.0/8\n10.0.0.0/\n", []string{"line 2"}, "merge")
	bad(t, "10.0.0.0/8\n10.0.0.0 /8\n", []string{"line 2"}, "merge")
	// mixed families
	bad(t, "10.0.0.0/8\n\n10.1.0.0/16\n::1\n10.2.0.0/16\n", []string{"mixed", "line 4"}, "merge")
	bad(t, "::1\n10.0.0.0/8\n", []string{"mixed", "line 2"}, "merge")
	bad(t, "10.0.0.0/8\n::ffff:10.0.0.0/104\n", []string{"mixed", "line 2"}, "merge")

	// the limit: 5000 networks are fine, 5001 are refused
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "10.%d.%d.0/24\n", 2*i/256, 2*i%256)
	}
	out, _, code := cidr(t, sb.String(), "merge")
	if code != 0 || len(strings.Split(strings.TrimSuffix(out, "\n"), "\n")) != 5000 {
		t.Errorf("5000 lines: code %d, out %d bytes", code, len(out))
	}
	sb.WriteString("10.255.255.0/24\n")
	bad(t, sb.String(), nil, "merge")
	// blank and comment lines are not counted
	filler := strings.Repeat("\n# x\n", 3000)
	ok(t, filler+strings.Repeat("10.0.0.0/8\n", 5000), lines("10.0.0.0/8"), 0, "merge")

	out, _, code = cidr(t, lines("10.0.0.0/25", "10.0.0.128/25", "10.0.2.0/24"), "merge", "--json")
	m := decode(t, out)
	if code != 0 || keys(m) != "count,prefixes,version" || m["version"] != float64(4) || m["count"] != float64(2) {
		t.Fatalf("merge json: %v", m)
	}
	ps := m["prefixes"].([]any)
	if len(ps) != 2 || ps[0] != "10.0.0.0/24" || ps[1] != "10.0.2.0/24" {
		t.Errorf("prefixes %v", ps)
	}
	out, _, _ = cidr(t, "::1\n", "--json", "merge")
	m = decode(t, out)
	if m["version"] != float64(6) {
		t.Errorf("v6 merge json: %v", m)
	}
}

func TestExclude(t *testing.T) {
	ok(t, "", lines("10.0.0.64/26", "10.0.0.128/25"), 0, "exclude", "10.0.0.0/24", "10.0.0.0/26")
	// the middle
	ok(t, "", lines("10.0.0.0/25", "10.0.0.128/26", "10.0.0.224/27"), 0, "exclude", "10.0.0.0/24", "10.0.0.192/27")
	// the end
	ok(t, "", lines("10.0.0.0/25", "10.0.0.128/26"), 0, "exclude", "10.0.0.0/24", "10.0.0.192/26")
	// several holes, in any order, overlapping
	ok(t, "", lines("10.0.0.0/26", "10.0.0.128/26", "10.0.0.224/27"), 0, "exclude", "10.0.0.0/24", "10.0.0.192/27", "10.0.0.64/26", "10.0.0.80/28", "10.0.0.64/26")
	// the /16 minus two /24
	ok(t, "", lines("10.0.1.0/24", "10.0.3.0/24", "10.0.4.0/22", "10.0.8.0/21", "10.0.16.0/20", "10.0.32.0/19", "10.0.64.0/18", "10.0.128.0/17"), 0, "exclude", "10.0.0.0/16", "10.0.0.0/24", "10.0.2.0/24")
	// nothing left
	ok(t, "", "", 0, "exclude", "10.0.0.0/24", "10.0.0.0/24")
	ok(t, "", "", 0, "exclude", "10.0.0.0/24", "10.0.0.0/8")
	ok(t, "", "", 0, "exclude", "10.0.0.0/24", "0.0.0.0/0")
	ok(t, "", "", 0, "exclude", "10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25")
	ok(t, "", "", 0, "exclude", "10.0.0.7", "10.0.0.7")
	ok(t, "", "{\"network\":\"10.0.0.0/24\",\"version\":4,\"count\":0,\"prefixes\":[]}\n", 0, "exclude", "10.0.0.0/24", "10.0.0.0/8", "--json")
	// nothing removed
	ok(t, "", lines("10.0.0.0/24"), 0, "exclude", "10.0.0.0/24", "192.168.0.0/16")
	ok(t, "", lines("10.0.0.0/24"), 0, "exclude", "10.0.0.0/24", "10.0.1.0", "9.255.255.255", "10.0.1.0/24")
	ok(t, "", lines("10.0.0.7/32"), 0, "exclude", "10.0.0.7", "10.0.0.8")
	// the edges of the space
	out, _, code := cidr(t, "", "exclude", "0.0.0.0/0", "255.255.255.255")
	ls := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if code != 0 || len(ls) != 32 || ls[0] != "0.0.0.0/1" || ls[1] != "128.0.0.0/2" || ls[31] != "255.255.255.254/32" {
		t.Errorf("exclude last address: code %d, %q", code, ls)
	}
	out, _, _ = cidr(t, "", "exclude", "0.0.0.0/0", "0.0.0.0")
	ls = strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(ls) != 32 || ls[0] != "0.0.0.1/32" || ls[1] != "0.0.0.2/31" || ls[31] != "128.0.0.0/1" {
		t.Errorf("exclude first address: %q", ls)
	}
	ok(t, "", lines("::1/128", "::2/127", "::4/126"), 0, "exclude", "::/125", "::", "::8/125")
	ok(t, "", lines("::/1"), 0, "exclude", "::/0", "8000::/1")
	out, _, _ = cidr(t, "", "exclude", "::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	ls = strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(ls) != 128 || ls[0] != "::/1" || ls[127] != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/128" {
		t.Errorf("v6 exclude: %d lines, %q", len(ls), ls[:2])
	}
	bad(t, "", []string{"mixed"}, "exclude", "10.0.0.0/8", "::1")
	bad(t, "", []string{"mixed"}, "exclude", "::/0", "10.0.0.0/8")
	bad(t, "", []string{"mixed"}, "exclude", "10.0.0.0/8", "10.0.0.0/24", "::ffff:10.0.0.0/120")
	bad(t, "", []string{"10.0.0.1/24"}, "exclude", "10.0.0.0/8", "10.0.0.1/24")
	bad(t, "", []string{"10.0.0.1/8"}, "exclude", "10.0.0.1/8", "10.0.0.1")

	out, _, code = cidr(t, "", "--json", "exclude", "10.0.0.0/24", "10.0.0.0/26")
	m := decode(t, out)
	if code != 0 || keys(m) != "count,network,prefixes,version" || m["network"] != "10.0.0.0/24" || m["version"] != float64(4) || m["count"] != float64(2) {
		t.Fatalf("exclude json: %v", m)
	}
	ps := m["prefixes"].([]any)
	if len(ps) != 2 || ps[0] != "10.0.0.64/26" || ps[1] != "10.0.0.128/25" {
		t.Errorf("prefixes %v", ps)
	}
}

func TestOverlaps(t *testing.T) {
	ok(t, lines("10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8"), lines("1: 10.0.0.0/8 contains 2: 10.1.0.0/16"), 1, "overlaps")
	ok(t, lines("10.1.0.0/16", "10.0.0.0/8"), lines("1: 10.1.0.0/16 within 2: 10.0.0.0/8"), 1, "overlaps")
	ok(t, lines("10.0.0.0/8", "10.0.0.0/8"), lines("1: 10.0.0.0/8 equals 2: 10.0.0.0/8"), 1, "overlaps")
	ok(t, lines("10.0.0.1", "10.0.0.1/32"), lines("1: 10.0.0.1/32 equals 2: 10.0.0.1/32"), 1, "overlaps")
	ok(t, lines("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/23"), "", 0, "overlaps")
	ok(t, lines("10.0.0.0/24"), "", 0, "overlaps")
	// the order of pairs, with line numbers counting every line
	in := "# header\n10.0.0.0/8\n\n10.1.0.0/16\n   \n10.1.2.0/24\n192.168.0.0/16\n10.0.0.0/8\n"
	ok(t, in, lines(
		"2: 10.0.0.0/8 contains 4: 10.1.0.0/16",
		"2: 10.0.0.0/8 contains 6: 10.1.2.0/24",
		"2: 10.0.0.0/8 equals 8: 10.0.0.0/8",
		"4: 10.1.0.0/16 contains 6: 10.1.2.0/24",
		"4: 10.1.0.0/16 within 8: 10.0.0.0/8",
		"6: 10.1.2.0/24 within 8: 10.0.0.0/8",
	), 1, "overlaps")
	ok(t, lines("2001:db8::/32", "2001:db8:1::/48", "::ffff:10.0.0.0/104"), lines("1: 2001:db8::/32 contains 2: 2001:db8:1::/48"), 1, "overlaps")
	ok(t, lines("::/0", "::1"), lines("1: ::/0 contains 2: ::1/128"), 1, "overlaps")
	// empty cases
	for _, in := range []string{"", "\n", "# c\n  \n"} {
		ok(t, in, "", 0, "overlaps")
		ok(t, in, "{\"version\":null,\"count\":0,\"pairs\":[]}\n", 0, "overlaps", "--json")
	}
	ok(t, lines("10.0.0.0/8"), "{\"version\":4,\"count\":0,\"pairs\":[]}\n", 0, "--json", "overlaps")
	ok(t, lines("::/8"), "{\"version\":6,\"count\":0,\"pairs\":[]}\n", 0, "--json", "overlaps")

	bad(t, "10.0.0.0/8\n::1\n", []string{"mixed", "line 2"}, "overlaps")
	bad(t, "10.0.0.0/8\n10.0.0.1/8\n", []string{"line 2"}, "overlaps")
	bad(t, "10.0.0.0/8\n\n10.0.0.0/8 # c\n", []string{"line 3"}, "overlaps")

	out, _, code := cidr(t, "# c\n10.0.0.0/8\n10.1.0.0/16\n", "overlaps", "--json")
	m := decode(t, out)
	if code != 1 || keys(m) != "count,pairs,version" || m["version"] != float64(4) || m["count"] != float64(1) {
		t.Fatalf("overlaps json: %v code %d", m, code)
	}
	p := m["pairs"].([]any)[0].(map[string]any)
	a, b := p["a"].(map[string]any), p["b"].(map[string]any)
	if keys(p) != "a,b,relation" || p["relation"] != "contains" || keys(a) != "line,prefix" || a["line"] != float64(2) || a["prefix"] != "10.0.0.0/8" ||
		b["line"] != float64(3) || b["prefix"] != "10.1.0.0/16" {
		t.Errorf("pair: %v", p)
	}

	// the limit: 447 equal lines make 99681 pairs, 448 make 100128
	out, _, code = cidr(t, strings.Repeat("10.0.0.0/8\n", 447), "overlaps")
	if code != 1 || strings.Count(out, "\n") != 99681 {
		t.Errorf("447 lines: code %d, %d pairs", code, strings.Count(out, "\n"))
	}
	bad(t, strings.Repeat("10.0.0.0/8\n", 448), nil, "overlaps")
	bad(t, strings.Repeat("10.0.0.0/8\n", 448), nil, "overlaps", "--json")
	// 5000 distinct networks: no pair, and one more is too many
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "10.%d.%d.0/24\n", i/256, i%256)
	}
	ok(t, sb.String(), "", 0, "overlaps")
	sb.WriteString("1.1.1.1\n")
	bad(t, sb.String(), nil, "overlaps")
}

func TestNoStdinRead(t *testing.T) {
	// commands that take arguments do not wait for or read standard input
	cmd := exec.Command(binPath, "info", "10.0.0.0/8")
	cmd.Dir = t.TempDir()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cmd.Stdin = r
	out, err := cmd.Output()
	if err != nil || !strings.HasPrefix(string(out), "prefix: 10.0.0.0/8\n") {
		t.Errorf("info with an open stdin: %q %v", out, err)
	}
}

// ---- unit tests of the pieces

func TestAddrString(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:0:0:1:0:0:1": "2001:db8::1:0:0:1",
		"1:0:0:2:0:0:0:3":      "1:0:0:2::3",
		"0:0:0:0:0:0:0:0":      "::",
		"1:0:2:3:4:5:6:7":      "1:0:2:3:4:5:6:7",
		"0:0:0:0:0:0:0:1":      "::1",
		"1:0:0:0:0:0:0:0":      "1::",
		"0:0:0:1:0:0:0:1":      "::1:0:0:0:1",
	} {
		a, ok := parseIPv6(in)
		if !ok {
			t.Fatalf("parse %s", in)
		}
		if got := addrString(6, a); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestRangePrefixes(t *testing.T) {
	a, _ := parseNetwork("10.0.0.1")
	b, _ := parseNetwork("10.0.0.6")
	var got []string
	for _, n := range rangePrefixes(4, a.first, b.first) {
		got = append(got, n.prefixString())
	}
	want := []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v want %v", got, want)
	}
	z := u128{}
	all := rangePrefixes(6, z, maxAddr(6))
	if len(all) != 1 || all[0].prefixString() != "::/0" {
		t.Errorf("whole IPv6 space: %v", all)
	}
}

func TestHostmask(t *testing.T) {
	for h := 0; h <= 128; h++ {
		m := hostmask(h)
		n := 0
		for i := 0; i < 64; i++ {
			n += int(m.lo >> uint(i) & 1)
			n += int(m.hi >> uint(i) & 1)
		}
		if n != h {
			t.Errorf("hostmask(%d) has %d bits", h, n)
		}
	}
}
