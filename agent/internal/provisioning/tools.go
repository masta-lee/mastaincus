// Package provisioning repairs Incus image tools and LXCFS resource visibility.
// Its scoped compatibility reload preserves running customers and host identity.
package provisioning

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Status struct {
	SecurityPackages string `json:"securityPackages,omitempty"`
	LegacyWorld      string `json:"legacyWorld,omitempty"`
	Version          int    `json:"version"`
	Ready            bool   `json:"ready"`
	CheckedAt        string `json:"checkedAt"`
	Error            string `json:"error,omitempty"`
	IncusCompat      string `json:"incusCompat,omitempty"`
	CompatRequest    string `json:"compatRequest,omitempty"`
	CompatHash       string `json:"compatHash,omitempty"`
	DiskTools        bool   `json:"diskTools,omitempty"`
}
type Engine struct {
	mu           sync.Mutex
	enabled      *bool
	status       Status
	guests       []Guest
	compatPermit *CompatPermit
	worldPermit  *LegacyWorldPermit
}
type Guest struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	MemoryMiB int    `json:"memoryMiB"`
}
type CompatPermit struct {
	RequestID    string              `json:"requestId"`
	ExpiresAt    string              `json:"expiresAt"`
	HostIdentity string              `json:"hostIdentity"`
	Guests       []CompatGuestPermit `json:"guests"`
}
type CompatGuestPermit struct {
	Name  string `json:"name"`
	UUID  string `json:"uuid"`
	State string `json:"state"`
}
type LegacyWorldPermit struct {
	Node      string `json:"node"`
	Recipe    string `json:"recipe"`
	ExpiresAt string `json:"expiresAt"`
}

func (e *Engine) SetLegacyWorldPermit(p *LegacyWorldPermit) {
	e.mu.Lock()
	e.worldPermit = p
	e.mu.Unlock()
}

func (e *Engine) SetCompatPermit(p *CompatPermit) { e.mu.Lock(); e.compatPermit = p; e.mu.Unlock() }

func New() *Engine                   { return &Engine{} }
func (e *Engine) SetPoolHost(v bool) { e.mu.Lock(); e.enabled = &v; e.mu.Unlock() }
func (e *Engine) SetGuests(v []Guest) {
	e.mu.Lock()
	e.guests = append([]Guest(nil), v...)
	e.mu.Unlock()
}
func (e *Engine) Status() Status { e.mu.Lock(); defer e.mu.Unlock(); return e.status }

// A withheld resource instruction list during maintenance is not proof that
// the host is empty. The signed compatibility permit retains real occupancy.
func emptyHostServiceCandidate(guests []Guest, permit *CompatPermit) bool {
	return len(guests) == 0 && (permit == nil || len(permit.Guests) == 0)
}
func (e *Engine) Run(ctx context.Context) {
	previousMemoryError := ""
	securityChecked := time.Time{}
	securityState := "pending"
	loadedChecked := time.Time{}
	lxcfsChecked := time.Time{}
	worldChecked := time.Time{}
	worldState := ""
	for ctx.Err() == nil {
		e.mu.Lock()
		enabled := e.enabled != nil && *e.enabled
		guests := append([]Guest(nil), e.guests...)
		permit := e.compatPermit
		worldPermit := e.worldPermit
		e.mu.Unlock()
		if enabled {
			if worldPermit != nil && time.Since(worldChecked) >= 6*time.Hour {
				worldContext, done := context.WithTimeout(ctx, 30*time.Second)
				if err := migrateLegacyAlpineWorld(worldContext, worldPermit); err != nil {
					worldChecked = time.Now().Add(-6*time.Hour + 5*time.Minute)
					worldState = "retry"
				} else {
					worldChecked = time.Now()
					worldState = "checked"
				}
				done()
			}
			if time.Since(securityChecked) > 6*time.Hour {
				securityContext, done := context.WithTimeout(ctx, 60*time.Second)
				if err := repairSecurityPackages(securityContext); err != nil {
					securityState = "retry"
					securityChecked = time.Now().Add(-6*time.Hour + 5*time.Minute)
				} else {
					securityState = "checked"
					securityChecked = time.Now()
				}
				done()
			}
			if (securityState == "checked" || securityState == "activation-required" || securityState == "verification-pending") && time.Since(loadedChecked) >= 5*time.Minute {
				activationContext, activated := context.WithTimeout(ctx, 30*time.Second)
				_ = repairGatewayDNSPythonSecurity(activationContext)
				activated()
				checkContext, done := context.WithTimeout(ctx, 5*time.Second)
				state, err := securityLoadedState(checkContext, "/proc")
				if err != nil {
					securityState = "verification-pending"
				} else {
					securityState = state
				}
				done()
				loadedChecked = time.Now()
			}
			c, cancel := context.WithTimeout(ctx, 180*time.Second)
			compatStatus, compatRequest, compatHashValue := incusCompatibilityStatus(c)
			if compatStatus == "needed" || compatStatus == "pending" {
				if permit != nil && validCompatPermit(permit) {
					_ = prepareIncusCompatibility(c, permit)
					compatStatus, compatRequest, compatHashValue = incusCompatibilityStatus(c)
				}
			}
			if compatStatus == "verified" && emptyHostServiceCandidate(guests, permit) && time.Since(lxcfsChecked) >= 6*time.Hour {
				// Resource instructions omit stopped guests and busy workflows.
				// They cannot prove vacancy. A read-only all-project inventory
				// must confirm empty before requesting an exclusive host fence.
				empty, inventoryErr := localHostMaintenanceEmpty(c)
				if inventoryErr != nil {
					securityState = "verification-pending"
				} else if empty {
					// Ask for the existing durable host fence even for a same-binary
					// maintenance pass. The Agent's guest list alone cannot authorize
					// interrupting a host service while a checkout is in flight.
					if validCompatPermit(permit) && len(permit.Guests) == 0 {
						// Package/service activation and DNS reload have independent
						// sixty-second deadlines inside the original maintenance lane.
						lxcfsError := repairEmptyHostServiceSecurity(c, permit)
						if lxcfsError == nil {
							lxcfsChecked = time.Now()
							loadedChecked = time.Time{}
						} else {
							// Release this bounded maintenance pass on a mirror/service
							// failure. Keep sales independent and retry in five minutes.
							lxcfsChecked = time.Now().Add(-6*time.Hour + 5*time.Minute)
							securityState = "retry"
						}
						compatStatus, compatRequest, compatHashValue = incusCompatibilityStatus(c)
					} else {
						compatStatus = "needed"
					}
				}
			}
			if compatStatus == "verified" {
				memoryError := ""
				if err := reconcileMemoryWatermark(c); err != nil && c.Err() == nil {
					memoryError = err.Error()
				}
				if memoryError != "" && memoryError != previousMemoryError {
					log.Printf("optional host memory reserve: %s", memoryError)
				}
				previousMemoryError = memoryError
			}
			err := repair(c)
			if err == nil {
				err = ensureResourceVisibility(c)
			}
			if err == nil {
				err = repairGuestVisibility(c, guests)
			}
			diskReady := err == nil && ensureDiskSupport(c) == nil
			cancel()
			s := Status{Version: 1, Ready: err == nil, DiskTools: diskReady, CheckedAt: time.Now().UTC().Format(time.RFC3339), IncusCompat: compatStatus, CompatRequest: compatRequest, CompatHash: compatHashValue}
			if err != nil {
				s.Error = "HOST_PROVISIONING_TOOLS_PENDING"
			}
			s.SecurityPackages = securityState
			s.LegacyWorld = worldState
			e.mu.Lock()
			e.status = s
			e.mu.Unlock()
		}
		timer := time.NewTimer(30 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func packagesFor(release string) ([]string, error) {
	fields := map[string]string{}
	for _, l := range strings.Split(release, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if ok {
			fields[k] = strings.Trim(v, "\"'")
		}
	}
	switch fields["ID"] {
	case "alpine":
		return []string{"apparmor-utils", "tar", "gzip", "xz", "squashfs-tools", "rsync", "lxcfs", "lxcfs-openrc", "util-linux", "lvm2", "lvm2-extra", "device-mapper", "btrfs-progs", "btrfs-progs-extra"}, nil
	case "debian", "ubuntu":
		return []string{"apparmor", "tar", "gzip", "xz-utils", "squashfs-tools", "rsync", "lxcfs", "util-linux", "lvm2", "thin-provisioning-tools", "btrfs-progs"}, nil
	default:
		return nil, fmt.Errorf("host distribution unsupported")
	}
}

var required = []string{"aa-exec", "tar", "gzip", "xz", "unsquashfs", "rsync", "nsenter", "lvm", "btrfs", "btrfstune", "mkfs.btrfs"}

func brokenToolPackages(tools []string, alpine bool) []string {
	owners := map[string][]string{"aa-exec": {"apparmor"}, "tar": {"tar"}, "gzip": {"gzip"}, "xz": {"xz-utils"},
		"unsquashfs": {"squashfs-tools"}, "rsync": {"rsync"}, "nsenter": {"util-linux"}, "lvm": {"lvm2", "thin-provisioning-tools"},
		"btrfs": {"btrfs-progs"}, "btrfstune": {"btrfs-progs"}, "mkfs.btrfs": {"btrfs-progs"}, "lxcfs": {"lxcfs"}}
	if alpine {
		owners["aa-exec"], owners["xz"], owners["lvm"], owners["lxcfs"] = []string{"apparmor-utils"}, []string{"xz"}, []string{"lvm2", "lvm2-extra", "device-mapper"}, []string{"lxcfs", "lxcfs-openrc"}
		for _, name := range []string{"btrfs", "btrfstune", "mkfs.btrfs"} {
			owners[name] = []string{"btrfs-progs", "btrfs-progs-extra"}
		}
	}
	seen, packages := map[string]bool{}, []string{}
	for _, name := range tools {
		for _, owner := range owners[name] {
			if !seen[owner] {
				seen[owner] = true
				packages = append(packages, owner)
			}
		}
	}
	return packages
}

func releaseFile() (string, error) { b, e := os.ReadFile("/etc/os-release"); return string(b), e }
