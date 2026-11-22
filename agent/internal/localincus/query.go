// Package localincus provides bounded read-only access to the host Unix API.
// No remote URL, credential, mutation method or customer socket is accepted.
package localincus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const Socket = "/var/lib/incus/unix.socket"
const MaxResponseBytes = 1 << 20

// Query keeps Incus CLI's raw-envelope and empty-metadata conventions, so an
// unsuccessful request can never be mistaken for an empty healthy inventory.
func Query(ctx context.Context, path string, raw bool) ([]byte, error) {
	info, err := os.Lstat(Socket)
	if err != nil || !trustedSocket(info) {
		return nil, fmt.Errorf("local Incus socket unavailable")
	}
	return querySocket(ctx, Socket, path, raw)
}

func querySocket(ctx context.Context, socket, path string, raw bool) ([]byte, error) {
	if path != "/1.0" && path != "/internal/ready" && !strings.HasPrefix(path, "/1.0/") || strings.ContainsAny(path, "\r\n#\\") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("local Incus query path invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := &http.Transport{DisableCompression: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("local Incus redirect rejected")
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://incus"+path, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes {
		return nil, fmt.Errorf("local Incus response exceeds limit or failed")
	}
	var envelope struct {
		Type       string          `json:"type"`
		StatusCode int             `json:"status_code"`
		Error      string          `json:"error"`
		Metadata   json.RawMessage `json:"metadata"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &envelope) != nil ||
		envelope.Type != "sync" || envelope.StatusCode != http.StatusOK || envelope.Error != "" || len(envelope.Metadata) == 0 || string(envelope.Metadata) == "null" && path != "/internal/ready" {
		return nil, fmt.Errorf("local Incus response not confirmed")
	}
	if raw {
		return data, nil
	}
	// The operations CLI suppresses {}, while its raw mode retains the proof.
	if strings.HasPrefix(path, "/1.0/operations") && strings.TrimSpace(string(envelope.Metadata)) == "{}" {
		return nil, nil
	}
	return envelope.Metadata, nil
}
