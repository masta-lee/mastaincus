package panel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"incudal-agent/internal/abuse"
	"incudal-agent/internal/config"
	"incudal-agent/internal/ingress"
	"incudal-agent/internal/protocol"
	"incudal-agent/internal/provisioning"
)

const heartbeatPath = "/api/agent/heartbeat"

type Client struct {
	panelURL    string
	agentID     string
	agentSecret string
	httpClient  *http.Client
}

type HeartbeatResult struct {
	AbusePolicy    *abuse.Instruction
	PortProtocol   *ingress.Instruction
	StatusCode     int
	Body           string
	OK             bool
	Upgrade        *UpgradeInstruction
	LatencyMs      int64
	PoolHostBBR    *bool
	ResourceGuests []provisioning.Guest
	IncusCompat    *provisioning.CompatPermit
	LegacyWorld    *provisioning.LegacyWorldPermit
}

type UpgradeInstruction struct {
	Signature    string `json:"signature"`
	Architecture string `json:"architecture"`
	Available    bool   `json:"available"`
	Version      string `json:"version"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
	Gzip         bool   `json:"gzip"`
	Size         int64  `json:"size"`
}

type heartbeatResponse struct {
	AbusePolicy    *abuse.Instruction              `json:"abusePolicy"`
	PortProtocol   *ingress.Instruction            `json:"portProtocol"`
	Upgrade        *UpgradeInstruction             `json:"upgrade"`
	PoolHostBBR    *bool                           `json:"poolHostBbr"`
	ResourceGuests []provisioning.Guest            `json:"resourceGuests"`
	IncusCompat    *provisioning.CompatPermit      `json:"incusCompat"`
	LegacyWorld    *provisioning.LegacyWorldPermit `json:"legacyWorld"`
}

func New(cfg config.Config) *Client {
	return &Client{
		panelURL:    strings.TrimRight(cfg.PanelURL, "/"),
		agentID:     cfg.AgentID,
		agentSecret: cfg.AgentSecret,
		httpClient: &http.Client{
			Timeout:       cfg.RequestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (client *Client) Heartbeat(ctx context.Context, payload map[string]any) (HeartbeatResult, error) {
	// A transient edge reset must not defer the next signed observation by a
	// whole heartbeat interval. Every attempt gets a fresh nonce/signature;
	// rejected identities, TLS trust, redirects and invalid bodies never retry.
	budget, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var result HeartbeatResult
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		requestCtx, stop := context.WithTimeout(budget, 5*time.Second)
		result, err = client.heartbeatOnce(requestCtx, payload)
		stop()
		if err == nil || ctx.Err() != nil || budget.Err() != nil || !transientHeartbeatFailure(result, err) {
			return result, err
		}
		if attempt == 2 {
			break
		}
		client.httpClient.CloseIdleConnections()
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-budget.Done():
			timer.Stop()
			return result, budget.Err()
		case <-timer.C:
		}
	}
	return result, err
}

func transientHeartbeatFailure(result HeartbeatResult, err error) bool {
	if result.StatusCode != 0 {
		return result.StatusCode == 408 || result.StatusCode == 429 || result.StatusCode == 502 || result.StatusCode == 503 || result.StatusCode == 504
	}
	var network net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &network) && network.Timeout()
}

func (client *Client) heartbeatOnce(ctx context.Context, payload map[string]any) (HeartbeatResult, error) {
	body, err := protocol.CanonicalJSON(payload)
	if err != nil {
		return HeartbeatResult{}, err
	}

	timestamp := protocol.NewTimestamp()
	nonce, err := protocol.NewNonce()
	if err != nil {
		return HeartbeatResult{}, err
	}
	bodyHash := protocol.BodySHA256(body)
	signingPayload := protocol.SigningPayload(http.MethodPost, heartbeatPath, timestamp, nonce, bodyHash)
	signature := protocol.Signature(client.agentSecret, signingPayload)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.panelURL+heartbeatPath, bytes.NewReader(body))
	if err != nil {
		return HeartbeatResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-incudal-agent-id", client.agentID)
	request.Header.Set("x-incudal-timestamp", timestamp)
	request.Header.Set("x-incudal-nonce", nonce)
	request.Header.Set("x-incudal-body-sha256", bodyHash)
	request.Header.Set("x-incudal-signature", signature)

	startedAt := time.Now()
	response, err := client.httpClient.Do(request)
	if err != nil {
		return HeartbeatResult{}, err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if len(responseBody) > 1024*1024 {
		return HeartbeatResult{}, fmt.Errorf("heartbeat response too large")
	}
	if err != nil {
		return HeartbeatResult{}, err
	}

	result := HeartbeatResult{
		StatusCode: response.StatusCode,
		Body:       string(responseBody),
		OK:         response.StatusCode >= 200 && response.StatusCode < 300,
		LatencyMs:  time.Since(startedAt).Milliseconds(),
	}
	if !result.OK {
		result.Body = ""
		return result, fmt.Errorf("heartbeat failed: status=%d", response.StatusCode)
	}

	var parsedResponse heartbeatResponse
	if err := json.Unmarshal(responseBody, &parsedResponse); err == nil {
		// Update authority must be bound to this signed request's nonce and the
		// complete response bytes, independent of DNS or a transport cache.
		signature := response.Header.Get("x-incudal-response-signature")
		mac := hmac.New(sha256.New, []byte(client.agentSecret))
		mac.Write([]byte("payincus/agent-response/v1\n" + nonce + "\n"))
		mac.Write(responseBody)
		decoded, decodeErr := hex.DecodeString(signature)
		if decodeErr == nil && hmac.Equal(decoded, mac.Sum(nil)) {
			result.Upgrade = parsedResponse.Upgrade
			result.PortProtocol = parsedResponse.PortProtocol
			result.AbusePolicy = parsedResponse.AbusePolicy
			result.PoolHostBBR = parsedResponse.PoolHostBBR
			result.ResourceGuests = parsedResponse.ResourceGuests
			result.IncusCompat = parsedResponse.IncusCompat
			result.LegacyWorld = parsedResponse.LegacyWorld
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(responseBody, &parsed); err == nil {
		parsed["latencyMs"] = result.LatencyMs
		if compact, err := json.Marshal(parsed); err == nil {
			result.Body = string(compact)
		}
	}
	return result, nil
}
