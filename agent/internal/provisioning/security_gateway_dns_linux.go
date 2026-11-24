//go:build linux

package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// This daemon only refreshes the existing WireGuard peer endpoint. Terminating
// its exact child lets the unchanged OpenRC supervisor load installed Python;
// it never stops WireGuard, Incus, SSH, a customer or its forwarding rules.
const gatewayDNSSecurityUnit = "#!/sbin/openrc-run\n# payincus-host-gateway-dns-v1\ndescription=\"Refresh enrolled PayIncus gateway DNS endpoint\"\ncommand=\"/usr/bin/python3\"\ncommand_args=\"-I -B /usr/local/libexec/incudal-gateway-dns --serve\"\nsupervisor=\"supervise-daemon\"\nrespawn_delay=10\nrespawn_max=0\npidfile=\"/run/incudal-gateway-dns.pid\"\noutput_log=\"/var/log/incudal-gateway-dns.log\"\nerror_log=\"/var/log/incudal-gateway-dns.log\"\ndepend() { need net; after wg-quick.incudal-mgmt; }\n"
const gatewayDNSSecurityHelperHash = "f3dbe6d0f91dab12dce0572c8da72d2339e7ba1054ba8c7b2c162bf3fb88272e"

type gatewayDNSProcess struct {
	pid, supervisor int
	start           string
	supervisorStart string
	pending         bool
	files           map[string]string
}

func gatewayDNSFileProof() (map[string]string, error) {
	files := map[string]string{}
	for _, path := range []string{"/etc/init.d/incudal-gateway-dns", "/usr/local/libexec/incudal-gateway-dns", "/etc/incudal-onboarding-id", "/etc/incudal-gateway-dns.json", "/etc/wireguard/incudal-mgmt.conf"} {
		data, err := readManagedClockFile(path)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data)
		files[path] = hex.EncodeToString(hash[:])
		if path == "/etc/init.d/incudal-gateway-dns" && string(data) != gatewayDNSSecurityUnit || path == "/usr/local/libexec/incudal-gateway-dns" && files[path] != gatewayDNSSecurityHelperHash {
			return nil, fmt.Errorf("gateway DNS service source is not reviewed")
		}
		if strings.HasPrefix(path, "/etc/") && path != "/etc/init.d/incudal-gateway-dns" {
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&0077 != 0 {
				return nil, fmt.Errorf("gateway DNS private configuration untrusted")
			}
		}
	}
	return files, nil
}

func gatewayDNSSupervisorArguments() string {
	return "supervise-daemon\x00incudal-gateway-dns\x00--start\x00--stdout\x00/var/log/incudal-gateway-dns.log\x00--stderr\x00/var/log/incudal-gateway-dns.log\x00--pidfile\x00/run/incudal-gateway-dns.pid\x00--respawn-delay\x0010\x00--respawn-max\x000\x00--respawn-period\x001800\x00/usr/bin/python3\x00--\x00-I\x00-B\x00/usr/local/libexec/incudal-gateway-dns\x00--serve\x00"
}

func managedGatewayDNSProcess(ctx context.Context) (gatewayDNSProcess, error) {
	files, err := gatewayDNSFileProof()
	if err != nil {
		return gatewayDNSProcess{}, err
	}
	pidfile, err := readManagedClockFile("/run/incudal-gateway-dns.pid")
	if err != nil {
		return gatewayDNSProcess{}, err
	}
	supervisor, err := strconv.Atoi(strings.TrimSpace(string(pidfile)))
	if err != nil || supervisor < 2 {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS supervisor identity invalid")
	}
	parent := filepath.Join("/proc", strconv.Itoa(supervisor))
	args, err := clockProcFile(parent+"/cmdline", 4096)
	if err != nil || string(args) != gatewayDNSSupervisorArguments() {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS supervisor arguments changed")
	}
	tool, err := systemTool("supervise-daemon")
	if err != nil {
		return gatewayDNSProcess{}, err
	}
	binary, err := filepath.EvalSymlinks(tool)
	actual, exeErr := os.Readlink(parent + "/exe")
	if err != nil || exeErr != nil || actual != binary {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS supervisor executable changed")
	}
	old, err := securityProcessLoaded(ctx, "/proc", supervisor)
	root, rootErr := clockProcessSharesRoot(parent)
	if err != nil || old || rootErr != nil || !root {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS supervisor authority unavailable")
	}
	python, err := filepath.EvalSymlinks("/usr/bin/python3")
	if err != nil || !strings.HasPrefix(python, "/usr/bin/python3.") {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS interpreter identity unreviewed")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 65536 {
		return gatewayDNSProcess{}, fmt.Errorf("gateway DNS process inventory unavailable")
	}
	parentStart, err := compatProcessStart(supervisor)
	if err != nil {
		return gatewayDNSProcess{}, err
	}
	result := gatewayDNSProcess{supervisor: supervisor, supervisorStart: parentStart, files: files}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			continue
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		process := filepath.Join("/proc", entry.Name())
		stat, err := clockProcFile(process+"/stat", 8192)
		if os.IsNotExist(err) {
			continue
		}
		at := strings.LastIndex(string(stat), ") ")
		if err != nil || at < 0 {
			return result, fmt.Errorf("gateway DNS process state unavailable")
		}
		fields := strings.Fields(string(stat[at+2:]))
		if len(fields) < 20 {
			return result, fmt.Errorf("gateway DNS process state invalid")
		}
		if fields[1] != strconv.Itoa(supervisor) || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		args, err := clockProcFile(process+"/cmdline", 4096)
		if err != nil || string(args) != "/usr/bin/python3\x00-I\x00-B\x00/usr/local/libexec/incudal-gateway-dns\x00--serve\x00" || result.pid != 0 {
			return result, fmt.Errorf("gateway DNS child identity changed")
		}
		actual, err := os.Readlink(process + "/exe")
		if err != nil || strings.TrimSuffix(actual, " (deleted)") != python {
			return result, fmt.Errorf("gateway DNS child executable changed")
		}
		old, err := securityProcessLoaded(ctx, "/proc", pid)
		root, rootErr := clockProcessSharesRoot(process)
		if err != nil || rootErr != nil || !root {
			return result, fmt.Errorf("gateway DNS child authority unavailable")
		}
		result.pid, result.start, result.pending = pid, fields[19], old || strings.HasSuffix(actual, " (deleted)")
	}
	if result.pid < 2 {
		return result, fmt.Errorf("gateway DNS supervised child pending")
	}
	return result, nil
}

func repairGatewayDNSPythonSecurity(ctx context.Context) error {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("gateway DNS process-handle architecture unreviewed")
	}
	if _, err := os.Lstat("/etc/init.d/incudal-gateway-dns"); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	before, err := managedGatewayDNSProcess(ctx)
	if err != nil || !before.pending {
		return err
	}
	// Linux AMD64 and ARM64 share these pidfd syscall numbers. Bind a kernel
	// process handle before the final identity read; no PID-reuse kill fallback.
	fd, _, errno := syscall.Syscall(434, uintptr(before.pid), 0, 0)
	if errno != 0 {
		return fmt.Errorf("gateway DNS exact process handle unavailable")
	}
	defer syscall.Close(int(fd))
	after, err := managedGatewayDNSProcess(ctx)
	if err != nil || ctx.Err() != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("gateway DNS authority changed before activation")
	}
	_, _, errno = syscall.Syscall6(424, fd, uintptr(syscall.SIGTERM), 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("gateway DNS exact process activation failed")
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		current, err := managedGatewayDNSProcess(ctx)
		if err == nil && current.pid != before.pid && current.supervisor == before.supervisor && current.supervisorStart == before.supervisorStart && !current.pending && reflect.DeepEqual(current.files, before.files) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("gateway DNS installed interpreter activation pending")
}
