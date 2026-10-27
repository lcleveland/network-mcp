// Package change holds the write pipeline's server-side records (#10 §2,
// §9) and the platform Driver interface.
// A plan is an opaque random ID keying an in-memory record: unsigned, voided
// by a restart, single-use, bound to one MCP session, expiring after
// PlanTTL. A change is an applied plan holding its device's slot until it
// is confirmed, rolled back or past its deadline.
package change

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const (
	PlanTTL  = 10 * time.Minute
	MaxPlans = 64 // live plans across all sessions; caps memory
)

var (
	ErrExpired = errors.New("plan expired; plan again")
	ErrUnknown = errors.New("unknown or already used plan_id")
)

// Plan binds everything apply must find unchanged.
type Plan struct {
	ID       string    `json:"plan_id"`
	Device   string    `json:"device"`
	Address  string    `json:"address"`  // the address dialed
	HostKey  string    `json:"host_key"` // pinned key fingerprint(s)
	Driver   string    `json:"driver"`
	Lines    []string  `json:"lines"` // normalized
	PreHash  string    `json:"pre_hash"`
	WriteRef string    `json:"write_ref"` // the ref name, never its contents
	Username string    `json:"username"`
	Reason   string    `json:"reason"`
	Session  string    `json:"-"`
	Expires  time.Time `json:"expires"`
}

type Store struct {
	Now       func() time.Time // tests fake the clock
	Expired   func(Plan)       // called once per plan that expires unused, for audit
	mu        sync.Mutex
	plans     map[string]Plan
	changes   map[string]*Change // by device; nil while apply or save holds the slot
	confirmed map[string]string  // device -> post-hash of the last change confirmed here
}

func NewStore() *Store {
	return &Store{Now: time.Now, Expired: func(Plan) {}, plans: map[string]Plan{},
		changes: map[string]*Change{}, confirmed: map[string]string{}}
}

// Conn is an open, privileged CLI session made with the write ref.
type Conn interface {
	Run(ctx context.Context, cmd string) (string, error)
	// Ask is Run that answers the first question matching q with Enter.
	Ask(ctx context.Context, cmd string, q *regexp.Regexp) (string, error)
	Close()
}

// Driver is a platform's half of a change (#10 §1). The caller dials,
// hashes, audits and keeps the records; id is the change_id.
type Driver interface {
	// Ready refuses apply unless the device can take a change now;
	// running is the unredacted running config.
	Ready(ctx context.Context, c Conn, running string) error
	// Apply sends lines under a device-side revert after minutes and
	// returns the device's diff. On error it has tried to revert.
	Apply(ctx context.Context, c Conn, id string, lines []string, minutes int) (string, error)
	Confirm(ctx context.Context, c Conn, id string) error
	Rollback(ctx context.Context, c Conn, id string) error
	// Pending reports a change left unconfirmed on the device by any process.
	Pending(ctx context.Context, c Conn) (bool, error)
	Save(ctx context.Context, c Conn) error
}

// Change is an applied, unconfirmed change. Its fields are fixed once
// committed; the lock serializes confirm, rollback and the deadline check,
// and Done is set under it when the change ends.
type Change struct {
	sync.Mutex
	ID       string
	Plan     Plan
	PostHash string
	Minutes  int
	Deadline time.Time
	Conn     Conn // the apply session, kept open as confirm's fallback
	Done     bool
}

var ErrUnknownChange = errors.New("unknown or finished change_id")

// Reserve takes device's slot, refusing a busy device or more than max
// slots in use. Apply and save hold it; reads never look at it.
func (s *Store) Reserve(device string, max int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, busy := s.changes[device]; busy {
		return fmt.Errorf("a change or save is already in progress on %s", device)
	}
	if len(s.changes) >= max {
		return fmt.Errorf("%d changes are pending (--max-pending-changes); confirm or roll one back first", len(s.changes))
	}
	s.changes[device] = nil
	return nil
}

// Release frees a slot that holds no committed change.
func (s *Store) Release(device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.changes[device] == nil {
		delete(s.changes, device)
	}
}

// Commit fills the reserved slot with an applied change.
func (s *Store) Commit(c *Change) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changes[c.Plan.Device] = c
}

// End frees the change's slot and closes its session; confirmed records
// its post-hash as the one save requires. The caller holds c's lock.
func (s *Store) End(c *Change, confirmed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Done = true
	if s.changes[c.Plan.Device] == c {
		delete(s.changes, c.Plan.Device)
	}
	if confirmed {
		s.confirmed[c.Plan.Device] = c.PostHash
	}
	if c.Conn != nil {
		c.Conn.Close()
	}
}

// Get returns a committed change of session; it may end before the caller locks it.
func (s *Store) Get(id, session string) (*Change, error) {
	for _, c := range s.Changes() {
		if c.ID == id && c.Plan.Session == session {
			return c, nil
		}
	}
	return nil, ErrUnknownChange
}

// Changes lists the committed changes.
func (s *Store) Changes() []*Change {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Change
	for _, c := range s.changes {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// Confirmed is the post-hash of the last change confirmed on device by this
// process, or "".
func (s *Store) Confirmed(device string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed[device]
}

// NewID is 128 bits from crypto/rand, hex.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b) // never fails (crypto/rand panics instead)
	return hex.EncodeToString(b)
}

// Add gives p an ID and expiry and stores it only if commit (the audit
// write) succeeds.
func (s *Store) Add(p Plan, commit func(Plan) error) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.plans) >= MaxPlans {
		return Plan{}, fmt.Errorf("%d plans are pending; wait for some to expire", MaxPlans)
	}
	p.ID, p.Expires = NewID(), s.Now().Add(PlanTTL)
	if err := commit(p); err != nil {
		return Plan{}, err
	}
	s.plans[p.ID] = p
	return p, nil
}

// Take consumes a plan for apply. A plan from another session is refused and
// kept; an expired one, or one whose host key changed, is dropped.
func (s *Store) Take(id, session, hostKey string) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.plans[id]
	if !ok || p.Session != session { // no hint that the ID exists in another session
		return Plan{}, ErrUnknown
	}
	delete(s.plans, id)
	switch {
	case !s.Now().Before(p.Expires):
		s.Expired(p)
		return p, ErrExpired
	case p.HostKey != hostKey:
		return p, fmt.Errorf("the pinned host key of %s changed since the plan; plan again", p.Device)
	}
	return p, nil
}

// Plans lists the live plans.
func (s *Store) Plans() []Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	var live []Plan
	for _, p := range s.plans {
		live = append(live, p)
	}
	return live
}

func (s *Store) prune() {
	for id, p := range s.plans {
		if !s.Now().Before(p.Expires) {
			delete(s.plans, id)
			s.Expired(p)
		}
	}
}
