// Package scan executes the manual scan jobs sent by the backend (docs/03-AGENT-PROTOCOL.md
// §6-§8): it receives them by long polling, verifies their signature, runs the discovery on
// the authorized networks only, reports progress, honours cancellation and uploads the
// results through the persistent local queue, so that nothing is lost when the backend is
// unreachable. The agent never starts a scan by itself: it only executes signed jobs, which
// the backend creates on an explicit user action.
package scan

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"shsc/agent/internal/cloud"
	"shsc/agent/internal/portscan"
)

// JobSchemaVersion is the job format understood by this agent.
const JobSchemaVersion = 1

// Limits of the accepted jobs (defence in depth: the backend enforces the same).
const (
	maxTargets    = 16
	maxHostsLimit = 4096
)

// Target is an authorized network of the scan.
type Target struct {
	NetworkID string `json:"networkId"`
	CIDR      string `json:"cidr"`
}

// Limits bound the load the scan puts on the network.
type Limits struct {
	MaxHosts           int         `json:"maxHosts"`
	RatePerSecond      int         `json:"ratePerSecond"`
	Concurrency        int         `json:"concurrency"`
	MaxDurationSeconds int64       `json:"maxDurationSeconds"`
	Ports              *PortLimits `json:"ports,omitempty"`
}

// PortLimits bound the port scan of the QUICK and STANDARD profiles (docs/08 §1).
type PortLimits struct {
	RatePerSecond        int `json:"ratePerSecond"`
	Concurrency          int `json:"concurrency"`
	PerHostConcurrency   int `json:"perHostConcurrency"`
	PerHostRatePerSecond int `json:"perHostRatePerSecond"`
	TimeoutMillis        int `json:"timeoutMillis"`
}

// valid checks the limits against the agent own maximums (defence in depth).
func (p *PortLimits) valid() bool {
	return p != nil && p.RatePerSecond > 0 && p.RatePerSecond <= 300 && p.Concurrency > 0 && p.Concurrency <= 256 &&
		p.PerHostConcurrency > 0 && p.PerHostConcurrency <= 8 && p.PerHostRatePerSecond > 0 &&
		p.PerHostRatePerSecond <= 50 && p.TimeoutMillis >= 200 && p.TimeoutMillis <= 5000
}

// ProfileDiscovery finds the hosts only; the other profiles also scan their ports.
const ProfileDiscovery = "DISCOVERY"

// Job is a verified scan job.
type Job struct {
	SchemaVersion int       `json:"schemaVersion"`
	ScanID        string    `json:"scanId"`
	AgentID       string    `json:"agentId"`
	HomeID        string    `json:"homeId"`
	Profile       string    `json:"profile"`
	Targets       []Target  `json:"targets"`
	Limits        Limits    `json:"limits"`
	IssuedAt      time.Time `json:"issuedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`

	// Prefixes are the parsed targets.
	Prefixes []netip.Prefix `json:"-"`
}

// ErrBadSignature means the job was not signed with the pinned backend key.
var ErrBadSignature = errors.New("scan job signature is not valid: job refused")

// Verify checks the signature with the pinned key and the content of the job: it must be
// for this agent, not expired, of a known profile and limited to private networks.
func Verify(signed cloud.SignedJob, pinnedKey, agentID string, now time.Time) (Job, error) {
	key, err := base64.RawURLEncoding.DecodeString(pinnedKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Job{}, errors.New("no valid job signing key is pinned: enroll the agent again")
	}
	payload, err := base64.RawURLEncoding.DecodeString(signed.Payload)
	if err != nil {
		return Job{}, fmt.Errorf("job payload is not base64url: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), payload, signature) {
		return Job{}, ErrBadSignature
	}
	var job Job
	if err := json.Unmarshal(payload, &job); err != nil {
		return Job{}, fmt.Errorf("job is not valid JSON: %w", err)
	}
	switch {
	case job.SchemaVersion != JobSchemaVersion:
		return Job{}, fmt.Errorf("unsupported job schema version %d", job.SchemaVersion)
	case job.AgentID != agentID:
		return Job{}, errors.New("the job is addressed to another agent")
	case !job.ExpiresAt.After(now):
		return Job{}, errors.New("the job has expired")
	case !knownProfile(job.Profile):
		return Job{}, fmt.Errorf("unsupported scan profile %q", job.Profile)
	case job.Profile != ProfileDiscovery && !job.Limits.Ports.valid():
		return Job{}, errors.New("the job has no valid port scan limits")
	case job.ScanID == "":
		return Job{}, errors.New("the job has no scan id")
	case len(job.Targets) == 0 || len(job.Targets) > maxTargets:
		return Job{}, errors.New("the job has no valid list of targets")
	case job.Limits.MaxHosts <= 0 || job.Limits.MaxHosts > maxHostsLimit || job.Limits.RatePerSecond <= 0 ||
		job.Limits.Concurrency <= 0 || job.Limits.MaxDurationSeconds <= 0:
		return Job{}, errors.New("the job has invalid limits")
	}
	for _, t := range job.Targets {
		prefix, err := netip.ParsePrefix(t.CIDR)
		if err != nil || prefix.Masked() != prefix || !prefix.Addr().IsPrivate() && !prefix.Addr().IsLinkLocalUnicast() {
			return Job{}, fmt.Errorf("target %q is not a private network: job refused", t.CIDR)
		}
		job.Prefixes = append(job.Prefixes, prefix)
	}
	return job, nil
}

// knownProfile: DISCOVERY or a port list known to this agent (QUICK, STANDARD).
func knownProfile(name string) bool {
	if name == ProfileDiscovery {
		return true
	}
	_, ok := portscan.DefaultLists.Profile(name)
	return ok
}
