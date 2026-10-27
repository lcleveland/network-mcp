// Package change holds the write pipeline's server-side records (#10 §2).
// A plan is an opaque random ID keying an in-memory record: unsigned, voided
// by a restart, single-use, bound to one MCP session, expiring after
// PlanTTL.
package change

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	Now     func() time.Time // tests fake the clock
	Expired func(Plan)       // called once per plan that expires unused, for audit
	mu      sync.Mutex
	plans   map[string]Plan
}

func NewStore() *Store {
	return &Store{Now: time.Now, Expired: func(Plan) {}, plans: map[string]Plan{}}
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
