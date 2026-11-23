//go:build linux

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const managedClockConfiguration = "# payincus-time-sync-v1\npool pool.ntp.org iburst maxsources 4\ndriftfile /var/lib/chrony/incudal-clock/chrony.drift\nrtcsync\nmaxslewrate 10000\ncmdport 0\n"

var errManagedClockStopped = errors.New("managed host clock service unavailable")

func managedClockUnit(binary string) string {
	return "#!/sbin/openrc-run\n# payincus-time-sync-v1\ncommand=\"" + binary + "\"\ncommand_args=\"-d -f /etc/chrony/incudal-clock.conf\"\nsupervisor=\"supervise-daemon\"\nrespawn_delay=10\nrespawn_max=0\noutput_log=\"/dev/null\"\nerror_log=\"/dev/null\"\nstart_pre() { checkpath --directory --mode 0750 --owner chrony:chrony /run/chrony; }\ndepend() { after net; }\n"
}

func readManagedClockFile(path string) ([]byte, error) {
	for parent := filepath.Dir(path); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			return nil, fmt.Errorf("host clock maintenance directory untrusted")
		}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0022 != 0 || info.Size() > 65536 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, fmt.Errorf("host clock maintenance file untrusted")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return nil, fmt.Errorf("host clock maintenance file budget exceeded")
	}
	return data, nil
}

func clockProcFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("host clock process budget exceeded")
	}
	return data, nil
}

func clockProcessSharesRoot(process string) (bool, error) {
	root, err := os.Stat("/")
	if err != nil {
		return false, err
	}
	actual, err := os.Stat(process + "/root")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(root, actual), nil
}

type clockSecurityProcess struct {
	pid           int
	binary, start string
	pending       bool
}

func verifiedManagedClockGroup(ctx context.Context, group int) bool {
	process, err := managedHostClockProcess(ctx)
	if err != nil || process.pending {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 65536 {
		return false
	}
	supervisors := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if ctx.Err() != nil {
			return false
		}
		root := filepath.Join("/proc", entry.Name())
		data, err := clockProcFile(root+"/stat", 8192)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false
		}
		end := strings.LastIndex(string(data), ") ")
		if end < 0 {
			return false
		}
		fields := strings.Fields(string(data[end+2:]))
		if len(fields) < 3 {
			return false
		}
		pgid, err := strconv.Atoi(fields[2])
		if err != nil {
			return false
		}
		if pgid != group || fields[0] == "Z" || fields[0] == "X" {
			continue
		}
		exe, err := os.Readlink(root + "/exe")
		if err != nil {
			return false
		}
		if entry.Name() == strconv.Itoa(process.pid) && exe == process.binary {
			continue
		}
		supervisor, err := systemTool("supervise-daemon")
		if err != nil {
			return false
		}
		actual, err := filepath.EvalSymlinks(supervisor)
		if err != nil || exe != actual {
			return false
		}
		args, err := clockProcFile(root+"/cmdline", 4096)
		expected := "supervise-daemon\x00incudal-clock\x00--start\x00--stdout\x00/dev/null\x00--stderr\x00/dev/null\x00--respawn-delay\x0010\x00--respawn-max\x000\x00--respawn-period\x001800\x00" + process.binary + "\x00--\x00-d\x00-f\x00/etc/chrony/incudal-clock.conf\x00"
		namespace, nsErr := os.Readlink(root + "/ns/pid")
		host, hostErr := os.Readlink("/proc/1/ns/pid")
		old, loadedErr := securityProcessLoaded(ctx, "/proc", pid)
		sharesRoot, rootErr := clockProcessSharesRoot(root)
		if err != nil || string(args) != expected || nsErr != nil || hostErr != nil || namespace != host || loadedErr != nil || old || rootErr != nil || !sharesRoot {
			return false
		}
		childStat, childErr := clockProcFile(filepath.Join("/proc", strconv.Itoa(process.pid), "stat"), 8192)
		end = strings.LastIndex(string(childStat), ") ")
		if childErr != nil || end < 0 {
			return false
		}
		childFields := strings.Fields(string(childStat[end+2:]))
		if len(childFields) < 2 || childFields[1] != entry.Name() {
			return false
		}
		supervisors++
		if supervisors > 1 {
			return false
		}
	}
	after, afterErr := managedHostClockProcess(ctx)
	return supervisors == 1 && afterErr == nil && !after.pending && after.pid == process.pid && after.start == process.start
}

func managedHostClockProcess(ctx context.Context) (clockSecurityProcess, error) {
	const configuration = "/etc/chrony/incudal-clock.conf"
	config, err := readManagedClockFile(configuration)
	if err != nil {
		return clockSecurityProcess{}, err
	}
	if string(config) != managedClockConfiguration {
		return clockSecurityProcess{}, fmt.Errorf("host clock configuration needs reviewed maintenance")
	}
	unit, err := readManagedClockFile("/etc/init.d/incudal-clock")
	if err != nil || string(unit) != managedClockUnit("/usr/sbin/chronyd") && string(unit) != managedClockUnit("/sbin/chronyd") {
		return clockSecurityProcess{}, fmt.Errorf("host clock service is not managed")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return clockSecurityProcess{}, err
	}
	host, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return clockSecurityProcess{}, err
	}
	result := clockSecurityProcess{}
	checked := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		checked++
		if checked > 4096 {
			return result, fmt.Errorf("host clock process budget exceeded")
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		root := filepath.Join("/proc", entry.Name())
		namespace, err := os.Readlink(root + "/ns/pid")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return result, err
		}
		if namespace != host {
			continue
		}
		sharesRoot, rootErr := clockProcessSharesRoot(root)
		if rootErr != nil {
			return result, rootErr
		}
		if !sharesRoot {
			continue
		}
		name, err := clockProcFile(root+"/comm", 256)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return result, err
		}
		comm := strings.TrimSpace(string(name))
		if comm == "ntpd" || comm == "systemd-timesyn" {
			return result, fmt.Errorf("host clock competing process exists")
		}
		if comm != "chronyd" {
			continue
		}
		args, err := clockProcFile(root+"/cmdline", 4096)
		if err != nil {
			return result, err
		}
		fields := strings.Split(strings.TrimRight(string(args), "\x00"), "\x00")
		if len(fields) != 4 || fields[1] != "-d" || fields[2] != "-f" || fields[3] != configuration || result.pid != 0 {
			return result, fmt.Errorf("host clock process authority changed")
		}
		exe, err := os.Readlink(root + "/exe")
		if err != nil {
			return result, err
		}
		binary := strings.TrimSuffix(exe, " (deleted)")
		if fields[0] != binary || string(unit) != managedClockUnit(binary) {
			return result, fmt.Errorf("host clock executable changed")
		}
		old, err := securityProcessLoaded(ctx, "/proc", pid)
		if err != nil {
			return result, err
		}
		start, err := compatProcessStart(pid)
		if err != nil {
			return result, err
		}
		result = clockSecurityProcess{pid: pid, binary: binary, start: start, pending: old || strings.HasSuffix(exe, " (deleted)")}
	}
	if result.pid == 0 {
		return result, errManagedClockStopped
	}
	return result, nil
}

func repairHostClockSecurity(ctx context.Context, permit *CompatPermit) error {
	if _, err := os.Stat("/etc/alpine-release"); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat("/etc/chrony/incudal-clock.conf"); os.IsNotExist(err) {
		return nil
	}
	before, err := managedHostClockProcess(ctx)
	if err != nil && !errors.Is(err, errManagedClockStopped) {
		return err
	}
	targets := append(append([]string{}, securityLeaves...), "chrony", "chrony-common", "chrony-openrc")
	if err := repairSecurityPackageSet(ctx, targets, func(ctx context.Context) error { return authorizeEmptySecurityHost(ctx, permit) }); err != nil {
		return fmt.Errorf("host clock signed package stage: %w", err)
	}
	unlocked, err := lock()
	if err != nil {
		return err
	}
	defer unlocked()
	if err := authorizeEmptySecurityHost(ctx, permit); err != nil {
		return err
	}
	current, err := managedHostClockProcess(ctx)
	if err != nil && !errors.Is(err, errManagedClockStopped) {
		return err
	}
	if current.pid != before.pid || current.start != before.start {
		return fmt.Errorf("host clock process changed during package maintenance")
	}
	if current.pid > 0 && !current.pending {
		return nil
	}
	binary := current.binary
	if current.pid == 0 {
		tool, toolErr := systemTool("chronyd")
		if toolErr != nil {
			return toolErr
		}
		binary, err = filepath.EvalSymlinks(tool)
		if err != nil {
			return err
		}
	}
	trustedBinary, err := openCompatFile(binary)
	if err != nil {
		return err
	}
	trustedBinary.Close()
	config, err := readManagedClockFile("/etc/chrony/incudal-clock.conf")
	if err != nil {
		return err
	}
	unit, err := readManagedClockFile("/etc/init.d/incudal-clock")
	if err != nil {
		return err
	}
	action := "restart"
	if current.pid == 0 {
		// A bounded interrupted activation can leave our service stopped. The
		// exact fixed unit, no competing clock and fresh empty-host authority
		// are required before resetting only its stale OpenRC markers.
		if err := managedClockHasNoSupervisor(ctx); err != nil {
			return err
		}
		if _, err := run(ctx, "rc-service", "incudal-clock", "zap"); err != nil {
			return err
		}
		action = "start"
	}
	if _, err := run(ctx, "rc-service", "incudal-clock", action); err != nil {
		return fmt.Errorf("host clock original service activation: %w", err)
	}
	after, err := managedHostClockProcess(ctx)
	if err != nil || after.pending || after.pid == before.pid {
		return fmt.Errorf("host clock installed patch activation pending")
	}
	configAfter, err := readManagedClockFile("/etc/chrony/incudal-clock.conf")
	if err != nil {
		return err
	}
	unitAfter, err := readManagedClockFile("/etc/init.d/incudal-clock")
	if err != nil {
		return err
	}
	if string(configAfter) != string(config) || string(unitAfter) != string(unit) {
		return fmt.Errorf("host clock original configuration changed")
	}
	return verifyEmptySecurityHost(ctx, permit)
}

func managedClockHasNoSupervisor(ctx context.Context) error {
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 65536 {
		return fmt.Errorf("host clock process inventory unavailable")
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		sharesRoot, rootErr := clockProcessSharesRoot(filepath.Join("/proc", entry.Name()))
		if rootErr != nil {
			return rootErr
		}
		if !sharesRoot {
			continue
		}
		data, err := clockProcFile(filepath.Join("/proc", entry.Name(), "cmdline"), 4096)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, arg := range strings.Split(string(data), "\x00") {
			if arg == "incudal-clock" || arg == "/etc/init.d/incudal-clock" {
				return fmt.Errorf("host clock original service still busy")
			}
		}
	}
	return nil
}
