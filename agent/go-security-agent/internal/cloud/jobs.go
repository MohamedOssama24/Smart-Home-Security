package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SignedJob is a scan job as delivered by the backend: the JSON payload (base64url) and its
// Ed25519 signature made with the backend job key. It must be verified before use.
type SignedJob struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"keyId"`
}

// Lease is the answer to an ack: the scan is RUNNING and must report progress regularly.
type Lease struct {
	LeaseSeconds            int64 `json:"leaseSeconds"`
	ProgressIntervalSeconds int64 `json:"progressIntervalSeconds"`
}

// Progress is the state of a running scan.
type Progress struct {
	Phase             string `json:"phase"`
	Percent           int    `json:"percent"`
	DevicesDiscovered int    `json:"devicesDiscovered"`
}

// ProgressAck carries the user's cancellation request.
type ProgressAck struct {
	CancelRequested bool  `json:"cancelRequested"`
	LeaseSeconds    int64 `json:"leaseSeconds"`
}

// Observation is a host seen during a scan.
type Observation struct {
	IP         string         `json:"ip"`
	MAC        string         `json:"mac,omitempty"`
	Method     string         `json:"method"`
	Interface  string         `json:"iface,omitempty"`
	Hostname   string         `json:"hostname,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	ObservedAt time.Time      `json:"observedAt"`
}

// PortService is the service identified on an open port.
type PortService struct {
	Name       string         `json:"name"`
	Product    string         `json:"product,omitempty"`
	Version    string         `json:"version,omitempty"`
	Status     string         `json:"status"` // PROBABLE or CONFIRMED
	Confidence string         `json:"confidence"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	TLS        map[string]any `json:"tls,omitempty"`
}

// PortResult is an open port of a host (closed and silent ports are only counted, in the
// PORTSCAN observation of the host).
type PortResult struct {
	IP         string       `json:"ip"`
	Protocol   string       `json:"protocol"`
	Port       int          `json:"port"`
	State      string       `json:"state"`
	Reason     string       `json:"reason,omitempty"`
	Service    *PortService `json:"service,omitempty"`
	ObservedAt time.Time    `json:"observedAt"`
}

// GatewayDevice is a device known to Home Assistant (it may have no IP: Zigbee, Z-Wave...).
type GatewayDevice struct {
	Name         string   `json:"name,omitempty"`
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	SWVersion    string   `json:"swVersion,omitempty"`
	Protocol     string   `json:"protocol"`
	MACs         []string `json:"macs"`
	Entities     int      `json:"entities"`
}

// HomeAssistant is the read-only inventory of the owner's Home Assistant (never the token).
type HomeAssistant struct {
	IP         string          `json:"ip"`
	Version    string          `json:"version,omitempty"`
	HTTPS      bool            `json:"https"`
	Devices    []GatewayDevice `json:"devices"`
	Truncated  bool            `json:"truncated,omitempty"`
	ObservedAt time.Time       `json:"observedAt"`
}

// ResultsBatch is one idempotent upload (same BatchSeq twice = no-op on the backend).
type ResultsBatch struct {
	SchemaVersion int            `json:"schemaVersion"`
	BatchSeq      int            `json:"batchSeq"`
	Observations  []Observation  `json:"observations"`
	Ports         []PortResult   `json:"ports,omitempty"`
	HomeAssistant *HomeAssistant `json:"homeAssistant,omitempty"`
	Icons         []DeviceIcon   `json:"icons,omitempty"`
	Identities    []Identity     `json:"identities,omitempty"`
}

// Identity is the account last seen on an IP address of the home (M24, ADR-083): Source is
// DIRECTORY (Active Directory logons) or FIREWALL (Sophos authentications).
type Identity struct {
	IP         string    `json:"ip"`
	Account    string    `json:"account"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observedAt"`
}

// DeviceIcon is the icon a device declares about itself (M23, ADR-077); Data is sent in base64.
type DeviceIcon struct {
	IP          string    `json:"ip"`
	Origin      string    `json:"origin"`
	ContentType string    `json:"contentType"`
	Width       int       `json:"width"`
	Height      int       `json:"height"`
	Data        []byte    `json:"data"`
	ObservedAt  time.Time `json:"observedAt"`
}

// Completion closes a scan once all its batches were uploaded.
type Completion struct {
	SchemaVersion int      `json:"schemaVersion"`
	TotalBatches  int      `json:"totalBatches"`
	Outcome       string   `json:"outcome"` // COMPLETED, CANCELLED or FAILED
	Warnings      []string `json:"warnings"`
	ErrorCode     string   `json:"errorCode,omitempty"`
}

// NextJob long-polls for a scan job; it returns nil, nil when no job arrived within wait.
func (c *Client) NextJob(ctx context.Context, accessToken string, wait time.Duration) (*SignedJob, error) {
	var job SignedJob
	path := "/api/v1/agent/jobs/next?wait=" + url.QueryEscape(fmt.Sprint(int(wait.Seconds())))
	if err := c.do(ctx, http.MethodGet, path, accessToken, nil, &job); err != nil {
		return nil, err
	}
	if job.Payload == "" { // 204 No Content
		return nil, nil
	}
	return &job, nil
}

// Ack takes the job: QUEUED → RUNNING.
func (c *Client) Ack(ctx context.Context, accessToken, scanID string) (Lease, error) {
	var out Lease
	err := c.do(ctx, http.MethodPost, scanPath(scanID, "ack"), accessToken, nil, &out)
	return out, err
}

// ReportProgress renews the lease and returns the cancellation request, if any.
func (c *Client) ReportProgress(ctx context.Context, accessToken, scanID string, p Progress) (ProgressAck, error) {
	var out ProgressAck
	err := c.do(ctx, http.MethodPost, scanPath(scanID, "progress"), accessToken, p, &out)
	return out, err
}

// UploadResults sends one batch of observations.
func (c *Client) UploadResults(ctx context.Context, accessToken, scanID string, batch ResultsBatch) error {
	return c.do(ctx, http.MethodPost, scanPath(scanID, "results"), accessToken, batch, nil)
}

// Complete closes the scan; the answer is its final state.
func (c *Client) Complete(ctx context.Context, accessToken, scanID string, done Completion) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := c.do(ctx, http.MethodPost, scanPath(scanID, "complete"), accessToken, done, &out)
	return out.Status, err
}

func scanPath(scanID, action string) string {
	return "/api/v1/agent/scans/" + url.PathEscape(scanID) + "/" + action
}
