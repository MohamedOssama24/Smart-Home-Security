// Package cloud is the HTTPS client of the agent API (/api/v1/agent). Only HTTPS is
// allowed, with TLS 1.2+ and certificate verification (system roots plus an optional CA
// file, e.g. the self-signed development certificate). Certificate checks are never skipped.
package cloud

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/capabilities"
)

const maxResponseBytes = 1 << 20

// APIError is an RFC 9457 problem returned by the backend.
type APIError struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("backend answered HTTP %d", e.Status)
	}
	return fmt.Sprintf("backend answered HTTP %d %s: %s", e.Status, e.Code, e.Detail)
}

// IsCode reports whether err is an APIError with the given code.
func IsCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// Client talks to one backend.
type Client struct {
	base *url.URL
	http *http.Client
}

// New validates the API URL (https only) and prepares a verifying TLS client.
func New(apiURL, caFile string) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(apiURL, "/"))
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid API URL %q", apiURL)
	}
	if base.Scheme != "https" {
		return nil, fmt.Errorf("the API URL must use https (got %q)", base.Scheme)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificate", caFile)
		}
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{base: base, http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, nil
}

// EnrollRequest is sent once, with the one-time enrollment token.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollmentToken"`
	PublicKey       string `json:"publicKey"`
	Name            string `json:"name,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agentVersion"`
}

// EnrollResponse identifies the new agent.
type EnrollResponse struct {
	AgentID      string `json:"agentId"`
	HomeID       string `json:"homeId"`
	CredentialID string `json:"credentialId"`
	// JobSigningKey is the backend public key (raw Ed25519, base64url) that signs scan jobs.
	JobSigningKey string `json:"jobSigningKey"`
}

// TokenResponse is a short-lived agent access token.
type TokenResponse struct {
	AccessToken string    `json:"accessToken"`
	TokenType   string    `json:"tokenType"`
	ExpiresIn   int64     `json:"expiresIn"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// SessionResponse is the identity seen by the backend (agent ↔ home binding).
type SessionResponse struct {
	AgentID        string    `json:"agentId"`
	HomeID         string    `json:"homeId"`
	HomeName       string    `json:"homeName"`
	CredentialID   string    `json:"credentialId"`
	TokenExpiresAt time.Time `json:"tokenExpiresAt"`
	JobSigningKey  string    `json:"jobSigningKey"`
}

// RotateResponse returns the id of the new credential.
type RotateResponse struct {
	CredentialID string `json:"credentialId"`
}

// SchemaVersion of the agent messages (the backend accepts N and N-1).
const SchemaVersion = 1

// HeartbeatRequest reports liveness and self-diagnosis. Interfaces is nil (JSON null) when
// the list did not change since the last accepted heartbeat: only its hash is sent.
type HeartbeatRequest struct {
	SchemaVersion  int                      `json:"schemaVersion"`
	AgentVersion   string                   `json:"agentVersion"`
	UptimeSeconds  int64                    `json:"uptimeSeconds"`
	InterfacesHash string                   `json:"interfacesHash"`
	Interfaces     []capabilities.Interface `json:"interfaces"`
	Capabilities   capabilities.Report      `json:"capabilities"`
	QueueDepth     int                      `json:"queueDepth"`
	LastError      string                   `json:"lastError,omitempty"`
}

// HeartbeatResponse carries the server clock and the heartbeat interval to use.
type HeartbeatResponse struct {
	ServerTime               time.Time `json:"serverTime"`
	HeartbeatIntervalSeconds int       `json:"heartbeatIntervalSeconds"`
}

// Event is a local agent event delivered through the persistent queue. ID is chosen by the
// agent, so a re-sent event is recognised as a duplicate by the backend.
type Event struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurredAt"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// EventsResponse counts new and already known events.
type EventsResponse struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
}

// Heartbeat sends the periodic liveness report.
func (c *Client) Heartbeat(ctx context.Context, accessToken string, req HeartbeatRequest) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/heartbeat", accessToken, req, &out)
	return out, err
}

// Events delivers a batch of queued events (idempotent).
func (c *Client) Events(ctx context.Context, accessToken string, events []Event) (EventsResponse, error) {
	var out EventsResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/events", accessToken,
		map[string]any{"schemaVersion": SchemaVersion, "events": events}, &out)
	return out, err
}

// Enroll registers the agent with a one-time enrollment token.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var out EnrollResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/enroll", "", req, &out)
	return out, err
}

// Token exchanges a signed assertion for an access token.
func (c *Client) Token(ctx context.Context, assertion string) (TokenResponse, error) {
	var out TokenResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/token", "", map[string]string{"assertion": assertion}, &out)
	return out, err
}

// Session returns the identity bound to the access token.
func (c *Client) Session(ctx context.Context, accessToken string) (SessionResponse, error) {
	var out SessionResponse
	err := c.do(ctx, http.MethodGet, "/api/v1/agent/session", accessToken, nil, &out)
	return out, err
}

// Rotate replaces the agent key; proof is an assertion signed with the new key.
func (c *Client) Rotate(ctx context.Context, accessToken, publicKey, proof string) (RotateResponse, error) {
	var out RotateResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/agent/credentials/rotate", accessToken,
		map[string]string{"publicKey": publicKey, "proof": proof}, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "shsc-agent/"+buildinfo.Get().Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		apiErr.Status = resp.StatusCode
		return apiErr
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected response from %s: %w", path, err)
	}
	return nil
}
