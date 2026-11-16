// Package agentauth implements the agent side of the authentication protocol
// (docs/03-AGENT-PROTOCOL.md): enrollment, signed-assertion login and key rotation.
// It is separate from user authentication: the agent never sees a user password or JWT.
package agentauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"shsc/agent/internal/assertion"
	"shsc/agent/internal/buildinfo"
	"shsc/agent/internal/cloud"
	"shsc/agent/internal/identity"
)

// ErrAlreadyEnrolled prevents overwriting an existing identity by mistake.
var ErrAlreadyEnrolled = errors.New("this agent is already enrolled; remove the state directory to enroll it again")

// Service runs the protocol against the backend recorded in the identity.
type Service struct {
	Store identity.Store
	Now   func() time.Time
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Enroll creates the key pair locally and registers the public key with a one-time token.
func (s Service) Enroll(ctx context.Context, apiURL, caFile, token, name string) (identity.State, error) {
	if s.Store.Exists() {
		return identity.State{}, ErrAlreadyEnrolled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return identity.State{}, errors.New("an enrollment token is required")
	}
	client, err := cloud.New(apiURL, caFile)
	if err != nil {
		return identity.State{}, err
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return identity.State{}, fmt.Errorf("generate key: %w", err)
	}
	hostname, _ := os.Hostname()
	resp, err := client.Enroll(ctx, cloud.EnrollRequest{
		EnrollmentToken: token,
		PublicKey:       identity.PublicKey(key),
		Name:            name,
		Hostname:        hostname,
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		AgentVersion:    buildinfo.Get().Version,
	})
	if err != nil {
		return identity.State{}, err
	}
	state := identity.State{
		AgentID:      resp.AgentID,
		HomeID:       resp.HomeID,
		CredentialID: resp.CredentialID,
		APIURL:       strings.TrimRight(apiURL, "/"),
		CAFile:       caFile,
		EnrolledAt:   s.now().UTC(),
	}
	if err := s.Store.Save(state, key); err != nil {
		return identity.State{}, fmt.Errorf("agent enrolled as %s but the identity could not be saved: %w", resp.AgentID, err)
	}
	return state, nil
}

// Session is an authenticated connection to the backend.
type Session struct {
	Client      *cloud.Client
	State       identity.State
	AccessToken string
	ExpiresAt   time.Time
}

// Login proves possession of the private key and obtains a short-lived access token.
// If a previous rotation was interrupted after the backend accepted the new key, the
// pending key is tried and promoted.
func (s Service) Login(ctx context.Context) (*Session, error) {
	state, key, err := s.Store.Load()
	if err != nil {
		return nil, err
	}
	client, err := cloud.New(state.APIURL, state.CAFile)
	if err != nil {
		return nil, err
	}
	session, err := s.login(ctx, client, state, key)
	if err == nil {
		return session, nil
	}
	pending, ok, pendingErr := s.Store.PendingKey()
	if pendingErr != nil || !ok || !cloud.IsCode(err, "INVALID_AGENT_ASSERTION") {
		return nil, err
	}
	session, retryErr := s.login(ctx, client, state, pending)
	if retryErr != nil {
		return nil, err
	}
	if err := s.Store.PromotePendingKey(); err != nil {
		return nil, fmt.Errorf("promote rotated key: %w", err)
	}
	return session, nil
}

func (s Service) login(ctx context.Context, client *cloud.Client, state identity.State, key ed25519.PrivateKey) (*Session, error) {
	signed, err := assertion.Sign(key, state.AgentID, assertion.AudienceToken, s.now(), assertion.MaxLifetime)
	if err != nil {
		return nil, err
	}
	token, err := client.Token(ctx, signed)
	if err != nil {
		return nil, err
	}
	return &Session{Client: client, State: state, AccessToken: token.AccessToken, ExpiresAt: token.ExpiresAt}, nil
}

// Check logs in and asks the backend which agent and home it recognises.
func (s Service) Check(ctx context.Context) (cloud.SessionResponse, error) {
	session, err := s.Login(ctx)
	if err != nil {
		return cloud.SessionResponse{}, err
	}
	info, err := session.Client.Session(ctx, session.AccessToken)
	if err != nil {
		return cloud.SessionResponse{}, err
	}
	if info.AgentID != session.State.AgentID || info.HomeID != session.State.HomeID {
		return info, fmt.Errorf("backend identity %s/%s does not match the local one %s/%s",
			info.AgentID, info.HomeID, session.State.AgentID, session.State.HomeID)
	}
	return info, nil
}

// RotateKey generates a new key, stores it as pending, proves possession to the backend
// and promotes it. The old key stops working immediately on the backend side.
func (s Service) RotateKey(ctx context.Context) (string, error) {
	session, err := s.Login(ctx)
	if err != nil {
		return "", err
	}
	next, err := identity.GenerateKey()
	if err != nil {
		return "", err
	}
	if err := s.Store.SavePendingKey(next); err != nil {
		return "", fmt.Errorf("save new key: %w", err)
	}
	proof, err := assertion.Sign(next, session.State.AgentID, assertion.AudienceRotate, s.now(), assertion.MaxLifetime)
	if err != nil {
		return "", err
	}
	resp, err := session.Client.Rotate(ctx, session.AccessToken, identity.PublicKey(next), proof)
	if err != nil {
		var apiErr *cloud.APIError
		if errors.As(err, &apiErr) {
			// definitive rejection: the backend kept the current key
			_ = s.Store.DiscardPendingKey()
		}
		// on network errors the pending key is kept: Login recovers it if the backend accepted it
		return "", err
	}
	if err := s.Store.PromotePendingKey(); err != nil {
		return "", fmt.Errorf("promote new key: %w", err)
	}
	state := session.State
	state.CredentialID = resp.CredentialID
	if err := s.Store.SaveState(state); err != nil {
		return "", err
	}
	return resp.CredentialID, nil
}
