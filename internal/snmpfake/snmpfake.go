// Package snmpfake is an in-process SNMP v2c agent for tests: a UDP loop on
// loopback that answers Get, GetNext and GetBulk from a sorted OID table
// loaded from .snmprec fixtures (snmpsim's OID|TYPE|VALUE format).
package snmpfake

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

type Agent struct {
	Host string
	Port int
}

type Options struct {
	Community string
	Files     []string // .snmprec fixtures
	// Back makes GetNext/GetBulk from the key OID answer the value OID, to
	// fake a broken agent whose OIDs do not increase.
	Back map[string]string
}

type entry struct {
	key []uint64
	pdu gosnmp.SnmpPDU
}

// Start serves the fixtures until the test ends. Requests with another
// community get no answer, like a real agent.
func Start(t testing.TB, o Options) *Agent {
	t.Helper()
	var tbl []entry
	for _, f := range o.Files {
		es, err := load(f)
		if err != nil {
			t.Fatal(err)
		}
		tbl = append(tbl, es...)
	}
	slices.SortFunc(tbl, func(a, b entry) int { return slices.Compare(a.key, b.key) })
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req, err := (&gosnmp.GoSNMP{Version: gosnmp.Version2c}).SnmpDecodePacket(buf[:n])
			if err != nil || req.Version != gosnmp.Version2c || req.Community != o.Community {
				continue
			}
			if b, err := answer(tbl, o.Back, req).MarshalMsg(); err == nil {
				conn.WriteToUDP(b, from)
			}
		}
	}()
	a := conn.LocalAddr().(*net.UDPAddr)
	return &Agent{Host: a.IP.String(), Port: a.Port}
}

func answer(tbl []entry, back map[string]string, req *gosnmp.SnmpPacket) *gosnmp.SnmpPacket {
	resp := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID}
	find := func(oid string) (int, bool) {
		return slices.BinarySearchFunc(tbl, key(oid), func(e entry, k []uint64) int { return slices.Compare(e.key, k) })
	}
	next := func(oid string) gosnmp.SnmpPDU {
		if to, ok := back[strings.TrimPrefix(oid, ".")]; ok {
			i, _ := find(to)
			return tbl[i].pdu
		}
		i, ok := find(oid)
		if ok {
			i++
		}
		if i >= len(tbl) {
			return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView}
		}
		return tbl[i].pdu
	}
	for _, v := range req.Variables {
		switch req.PDUType {
		case gosnmp.GetRequest:
			if i, ok := find(v.Name); ok {
				resp.Variables = append(resp.Variables, tbl[i].pdu)
			} else {
				resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
			}
		case gosnmp.GetNextRequest:
			resp.Variables = append(resp.Variables, next(v.Name))
		case gosnmp.GetBulkRequest: // one repeater, as the client sends
			cur := v.Name
			for range req.MaxRepetitions {
				p := next(cur)
				resp.Variables = append(resp.Variables, p)
				if p.Type == gosnmp.EndOfMibView {
					break
				}
				cur = p.Name
			}
		}
	}
	return resp
}

func key(oid string) []uint64 {
	var k []uint64
	for p := range strings.SplitSeq(strings.TrimPrefix(oid, "."), ".") {
		n, _ := strconv.ParseUint(p, 10, 64)
		k = append(k, n)
	}
	return k
}

// load parses a .snmprec file: OID|TYPE|VALUE with snmpsim's numeric BER
// tags, an x suffix meaning a hex value. # starts a comment.
func load(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []entry
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s:%d: want OID|TYPE|VALUE", path, n)
		}
		oid, tag, val := parts[0], parts[1], parts[2]
		raw := []byte(val)
		if t, ok := strings.CutSuffix(tag, "x"); ok {
			if raw, err = hex.DecodeString(val); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, n, err)
			}
			tag, val = t, string(raw)
		}
		p := gosnmp.SnmpPDU{Name: "." + oid}
		num := func() uint64 { u, e := strconv.ParseUint(val, 10, 64); err = e; return u }
		switch tag {
		case "2":
			p.Type = gosnmp.Integer
			i, e := strconv.Atoi(val)
			p.Value, err = i, e
		case "4":
			p.Type, p.Value = gosnmp.OctetString, raw
		case "5":
			p.Type = gosnmp.Null
		case "6":
			p.Type, p.Value = gosnmp.ObjectIdentifier, "."+val
		case "64":
			p.Type, p.Value = gosnmp.IPAddress, val
		case "65":
			p.Type, p.Value = gosnmp.Counter32, uint32(num())
		case "66":
			p.Type, p.Value = gosnmp.Gauge32, uint32(num())
		case "67":
			p.Type, p.Value = gosnmp.TimeTicks, uint32(num())
		case "70":
			p.Type, p.Value = gosnmp.Counter64, num()
		default:
			return nil, fmt.Errorf("%s:%d: unsupported type %q", path, n, tag)
		}
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		out = append(out, entry{key(oid), p})
	}
	return out, sc.Err()
}
