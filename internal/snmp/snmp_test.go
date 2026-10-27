package snmp_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/mib"
	"github.com/lcleveland/network-mcp/internal/snmp"
	"github.com/lcleveland/network-mcp/internal/snmpfake"
)

const community = "fake-community-x"

func TestMain(m *testing.M) {
	if err := mib.Load(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func fixtures(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, filepath.Join("..", "..", "testdata", "snmp", n+".snmprec"))
	}
	return out
}

func dial(t *testing.T, o snmpfake.Options, comm string) *snmp.Client {
	t.Helper()
	o.Community = community
	a := snmpfake.Start(t, o)
	c, err := snmp.Dial(context.Background(), snmp.Target{
		Addr: netip.MustParseAddr(a.Host), Port: a.Port, Timeout: 200 * time.Millisecond,
		Cred: creds.SNMP{Version: "v2c", Community: comm},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func all() snmpfake.Options {
	return snmpfake.Options{Files: fixtures("system", "if-mib", "entity", "denied")}
}

func TestGet(t *testing.T) {
	c := dial(t, all(), community)
	r, err := c.Get([]string{"1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.2.1.6.1", "1.3.6.1.2.1.1.99.0"})
	if err != nil {
		t.Fatal(err)
	}
	want := []snmp.Row{
		{OID: "1.3.6.1.2.1.1.5.0", Name: "SNMPv2-MIB::sysName.0", Type: "OctetString", Value: "dev1.example.net"},
		{OID: "1.3.6.1.2.1.1.3.0", Name: "DISMAN-EVENT-MIB::sysUpTimeInstance", Type: "TimeTicks", Value: uint32(123456789)},
		{OID: "1.3.6.1.2.1.2.2.1.6.1", Name: "IF-MIB::ifPhysAddress.1", Type: "OctetString", Value: "0x00005e005301"},
		{OID: "1.3.6.1.2.1.1.99.0", Name: "SNMPv2-MIB::system.99.0", Type: "NoSuchObject", Value: nil},
	}
	for i, w := range want {
		if i >= len(r.Rows) || r.Rows[i] != w {
			t.Errorf("row %d: %+v, want %+v", i, r.Rows, w)
		}
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "NoSuchObject") {
		t.Errorf("warnings: %v", r.Warnings)
	}
}

func TestWalkStops(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		c := dial(t, all(), community)
		r, err := c.Walk("1.3.6.1.2.1.1", "", bulk, snmp.DefaultRows)
		if err != nil || len(r.Rows) != 7 || r.Truncation != nil || r.Rows[6].OID != "1.3.6.1.2.1.1.7.0" {
			t.Errorf("bulk=%v subtree exit: %+v %v", bulk, r, err)
		}
		c = dial(t, snmpfake.Options{Files: fixtures("entity")}, community)
		r, err = c.Walk("1.3.6.1.2.1.47", "", bulk, snmp.DefaultRows)
		if err != nil || len(r.Rows) != 18 || r.Truncation != nil {
			t.Errorf("bulk=%v endOfMibView: %d rows %v", bulk, len(r.Rows), err)
		}
	}
}

// Resuming with each hint's after walks the whole table exactly once.
func TestWalkCapsResume(t *testing.T) {
	for _, tc := range []struct {
		bulk    bool
		max     int
		reason  string
		maxRuns int
	}{{true, snmp.MaxRows, "bytes", 10}, {false, 500, "rows", 10}, {true, 100, "rows", 30}} {
		c := dial(t, all(), community)
		var rows []snmp.Row
		after, runs := "", 0
		for ; runs < tc.maxRuns; runs++ {
			r, err := c.Walk("1.3.6.1.2.1.2.2", after, tc.bulk, tc.max)
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := json.Marshal(r); len(b) > 60<<10 {
				t.Errorf("result is %d bytes", len(b))
			}
			rows = append(rows, r.Rows...)
			if r.Truncation == nil {
				break
			}
			if r.Truncation.Reason != tc.reason || r.Truncation.Hint != "use after: "+r.Rows[len(r.Rows)-1].OID {
				t.Fatalf("%+v: truncation %+v", tc, r.Truncation)
			}
			after = strings.TrimPrefix(r.Truncation.Hint, "use after: ")
		}
		if runs == 0 || len(rows) != 76*22 {
			t.Errorf("%+v: %d runs, %d rows", tc, runs, len(rows))
		}
		for i := 1; i < len(rows); i++ {
			if snmp.Compare(rows[i-1].OID, rows[i].OID) >= 0 {
				t.Fatalf("%+v: rows out of order at %d", tc, i)
			}
		}
	}
}

func TestWalkDecreasing(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		c := dial(t, snmpfake.Options{Files: fixtures("system"), Back: map[string]string{"1.3.6.1.2.1.1.3.0": "1.3.6.1.2.1.1.1.0"}}, community)
		r, err := c.Walk("1.3.6.1.2.1.1", "", bulk, snmp.DefaultRows)
		if err == nil || !strings.Contains(err.Error(), "must increase") || len(r.Rows) != 3 {
			t.Errorf("bulk=%v: %d rows, %v", bulk, len(r.Rows), err)
		}
	}
}

func TestDenied(t *testing.T) {
	for _, oid := range []string{"1.3.6.1.6.3.18", "1.3.6.1.6.3.18.1.1.1.2.116.49", "1.3.6.1.6.3.15.1"} {
		if snmp.Allowed(oid) == nil {
			t.Errorf("%s allowed", oid)
		}
	}
	for _, oid := range []string{"1.3.6.1.6.3", "1.3.6.1.6.3.180", "1.3.6.1.2.1.1"} {
		if err := snmp.Allowed(oid); err != nil {
			t.Errorf("%s: %v", oid, err)
		}
	}
	// a walk above the denied subtrees withholds what is inside them
	c := dial(t, snmpfake.Options{Files: fixtures("system", "denied")}, community)
	r, err := c.Walk("1.3.6.1.6", "", true, snmp.DefaultRows)
	b, _ := json.Marshal(r)
	if err != nil || len(r.Rows) != 0 || strings.Contains(string(b), "planted") || !strings.Contains(string(b), "2 varbinds") {
		t.Errorf("walk: %s %v", b, err)
	}
}

func TestWrongCommunity(t *testing.T) {
	c := dial(t, all(), "wrong-community-y")
	_, err := c.Get([]string{"1.3.6.1.2.1.1.5.0"})
	if err == nil || strings.Contains(err.Error(), "community") {
		t.Errorf("%v", err)
	}
}
