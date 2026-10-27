// Package snmp reads devices over SNMP v2c or v3 authPriv with gosnmp. It
// only reads: no Set, no trap listener, and gosnmp's AppOpts "c" (skip the
// increasing-OID check) stays unset.
package snmp

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/lcleveland/network-mcp/internal/creds"
	"github.com/lcleveland/network-mcp/internal/mib"
	"github.com/lcleveland/network-mcp/internal/output"
)

// Denied subtrees (snmpCommunityMIB, usmMIB) hold communities and USM keys:
// never requested, never returned.
var Denied = []string{"1.3.6.1.6.3.18", "1.3.6.1.6.3.15"}

const (
	MaxOIDs        = 16
	MaxRepetitions = 25
	DefaultRows    = 500
	MaxRows        = 5000
	SysUpTime      = "1.3.6.1.2.1.1.3.0"
)

// Row is one varbind. Value is a number, a string (printable OctetString,
// OID, IpAddress), 0x-prefixed hex, or null.
type Row struct {
	OID   string `json:"oid"`
	Name  string `json:"name,omitempty"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type Result struct {
	Rows       []Row              `json:"rows"`
	Warnings   []string           `json:"warnings,omitempty"`
	Redactions int                `json:"_redactions"`
	Truncation *output.Truncation `json:"_truncation,omitempty"`
	withheld   int
}

type Target struct {
	Addr    netip.Addr
	Port    int // 0 means 161
	Cred    creds.SNMP
	Timeout time.Duration // per request; one retry
}

// Client is one device session; not for concurrent use.
type Client struct {
	g      *gosnmp.GoSNMP
	ctx    context.Context
	cancel context.CancelCauseFunc
}

// ErrRejected: the agent answered but gosnmp rejected the answer, typically
// a v3 wrong-digest report, which arrives unauthenticated.
var ErrRejected = errors.New("the agent's answer failed authentication or decoding; not retried (check the SNMP credentials)")

// Dial opens a UDP session. A request is retried once on timeout only:
// gosnmp would also retry an answer it rejects, such as a v3 auth failure,
// so the retry is cancelled when the attempt got an answer.
func Dial(ctx context.Context, t Target) (*Client, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	answered := false
	g := &gosnmp.GoSNMP{
		Target: t.Addr.String(), Port: uint16(cmp.Or(t.Port, 161)), Context: ctx,
		Timeout: t.Timeout, Retries: 1, MaxOids: MaxOIDs,
		Version: gosnmp.Version2c, Community: t.Cred.Community,
		OnSent: func(*gosnmp.GoSNMP) { answered = false },
		OnRecv: func(*gosnmp.GoSNMP) { answered = true },
		OnRetry: func(*gosnmp.GoSNMP) {
			if answered {
				cancel(ErrRejected)
			}
		},
	}
	if t.Cred.Version == "v3" {
		g.Version, g.SecurityModel, g.MsgFlags = gosnmp.Version3, gosnmp.UserSecurityModel, gosnmp.AuthPriv
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 t.Cred.Username,
			AuthenticationProtocol:   creds.SNMPAuth[strings.ToUpper(t.Cred.AuthProtocol)],
			AuthenticationPassphrase: t.Cred.AuthPassword,
			PrivacyProtocol:          creds.SNMPPriv[strings.ToUpper(t.Cred.PrivProtocol)],
			PrivacyPassphrase:        t.Cred.PrivPassword,
		}
	}
	if err := g.Connect(); err != nil {
		cancel(nil)
		return nil, err
	}
	return &Client{g, ctx, cancel}, nil
}

func (c *Client) Close() { c.g.Close(); c.cancel(nil) }

// err names a cancelled retry instead of gosnmp's bare context error.
func (c *Client) err(err error) error {
	if err != nil && errors.Is(context.Cause(c.ctx), ErrRejected) {
		return ErrRejected
	}
	return err
}

// Allowed refuses a numeric OID inside a denied subtree.
func Allowed(oid string) error {
	for _, d := range Denied {
		if Within(oid, d) {
			return fmt.Errorf("OID %s is inside the denied subtree %s (%s); it holds credentials", oid, d, mib.Name(d))
		}
	}
	return nil
}

// Within reports whether numeric oid is root or below it.
func Within(oid, root string) bool { return oid == root || strings.HasPrefix(oid, root+".") }

// Get reads up to MaxOIDs numeric OIDs, each already passed by Allowed.
func (c *Client) Get(oids []string) (*Result, error) {
	pkt, err := c.g.Get(dotted(oids))
	if err != nil {
		return nil, c.err(err)
	}
	if pkt.Error != gosnmp.NoError {
		return nil, fmt.Errorf("agent answered %s for varbind %d", pkt.Error, pkt.ErrorIndex)
	}
	r := &Result{Rows: []Row{}}
	for _, v := range pkt.Variables {
		if row, ok := r.row(v); ok {
			r.Rows = append(r.Rows, row)
		}
	}
	r.done()
	return r, nil
}

// Walk reads the subtree under root with GETNEXT, or GETBULK when bulk,
// starting after after (or root). It stops on leaving the subtree,
// endOfMibView, maxRows rows or the result budget; the last two set
// Truncation with an after hint. An OID that does not increase ends the
// walk with an error, keeping the rows read so far.
func (c *Client) Walk(root, after string, bulk bool, maxRows int) (*Result, error) {
	r := &Result{Rows: []Row{}}
	defer r.done()
	cur, size := cmp.Or(after, root), 0
	for {
		var (
			pkt *gosnmp.SnmpPacket
			err error
		)
		if bulk {
			pkt, err = c.g.GetBulk(dotted([]string{cur}), 0, MaxRepetitions)
		} else {
			pkt, err = c.g.GetNext(dotted([]string{cur}))
		}
		if err != nil {
			return r, c.err(err)
		}
		if pkt.Error != gosnmp.NoError {
			return r, fmt.Errorf("agent answered %s", pkt.Error)
		}
		if len(pkt.Variables) == 0 {
			return r, nil
		}
		for _, v := range pkt.Variables {
			oid := strings.TrimPrefix(v.Name, ".")
			if v.Type == gosnmp.EndOfMibView || !Within(oid, root) {
				return r, nil
			}
			if Compare(oid, cur) <= 0 {
				return r, fmt.Errorf("agent returned %s after %s: OIDs must increase, walk stopped", oid, cur)
			}
			cur = oid
			row, ok := r.row(v)
			if !ok {
				continue
			}
			b, _ := json.Marshal(row)
			reason := ""
			switch {
			case len(r.Rows) >= maxRows:
				reason = "rows"
			case size+len(b)+1 > output.MaxResult-output.Envelope:
				reason = "bytes"
			}
			if reason != "" {
				hint := "narrow the oid"
				if n := len(r.Rows); n > 0 {
					hint = "use after: " + r.Rows[n-1].OID
				}
				r.Truncation = &output.Truncation{Reason: reason, Shown: len(r.Rows), Hint: hint}
				return r, nil
			}
			r.Rows, size = append(r.Rows, row), size+len(b)+1
		}
	}
}

// row converts a varbind; false means it was withheld.
func (r *Result) row(v gosnmp.SnmpPDU) (Row, bool) {
	oid := strings.TrimPrefix(v.Name, ".")
	if Allowed(oid) != nil {
		r.withheld++
		return Row{}, false
	}
	row := Row{OID: oid, Name: mib.Name(oid), Type: v.Type.String(), Value: v.Value}
	switch v.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		row.Value = nil
		r.Warnings = append(r.Warnings, oid+": "+row.Type)
	case gosnmp.Null:
		row.Value = nil
	case gosnmp.ObjectIdentifier:
		row.Value = strings.TrimPrefix(fmt.Sprint(v.Value), ".")
	case gosnmp.OctetString, gosnmp.Opaque, gosnmp.BitString:
		b, _ := v.Value.([]byte)
		if printable(b) {
			s, n := output.Field(string(b), output.LongCap)
			row.Value, r.Redactions = s, r.Redactions+n
		} else {
			row.Value = output.Cap("0x"+hex.EncodeToString(b), output.LongCap)
		}
	}
	return row, true
}

func (r *Result) done() {
	if r.withheld > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d varbinds inside a denied subtree (%s) were withheld", r.withheld, strings.Join(Denied, ", ")))
		r.withheld = 0
	}
}

func printable(b []byte) bool {
	return utf8.Valid(b) && !strings.ContainsFunc(string(b), func(r rune) bool {
		return !unicode.IsPrint(r) && r != '\t' && r != '\n' && r != '\r'
	})
}

// Compare orders numeric OIDs by sub-identifier.
func Compare(a, b string) int { return slices.Compare(subids(a), subids(b)) }

func subids(oid string) []uint64 {
	var out []uint64
	for p := range strings.SplitSeq(oid, ".") {
		n, _ := strconv.ParseUint(p, 10, 64)
		out = append(out, n)
	}
	return out
}

func dotted(oids []string) []string {
	out := make([]string, len(oids))
	for i, o := range oids {
		out[i] = "." + o
	}
	return out
}
