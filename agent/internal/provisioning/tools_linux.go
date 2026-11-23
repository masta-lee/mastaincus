//go:build linux

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"incudal-agent/internal/localincus"
)

// Resolve only root-owned system executables. PATH supplied by a service or
// customer cannot substitute an executable for a successful readiness receipt.
func systemTool(name string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		p := filepath.Join(dir, name)
		resolved, e := filepath.EvalSymlinks(p)
		if e != nil {
			continue
		}
		muslLdd := name == "ldd" && (resolved == "/lib/ld-musl-x86_64.so.1" || resolved == "/lib/ld-musl-aarch64.so.1")
		if !muslLdd && !strings.HasPrefix(resolved, "/usr/") && !strings.HasPrefix(resolved, "/bin/") && !strings.HasPrefix(resolved, "/sbin/") {
			continue
		}
		i, e := os.Stat(resolved)
		if e != nil || !i.Mode().IsRegular() || i.Mode()&0111 == 0 || i.Mode()&0022 != 0 {
			continue
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			continue
		}
		return p, nil
	}
	return "", fmt.Errorf("required host tool missing")
}
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runWithFiles(ctx, name, nil, args...)
}
func runWithFiles(ctx context.Context, name string, files []*os.File, args ...string) ([]byte, error) {
	if name == "incus" && len(files) == 0 {
		if len(args) == 2 && args[0] == "query" {
			return localincus.Query(ctx, args[1], false)
		}
		if len(args) == 3 && args[0] == "query" && args[1] == "--raw" {
			return localincus.Query(ctx, args[2], true)
		}
		if len(args) == 2 && args[0] == "list" && args[1] == "--format=json" {
			return localincus.Query(ctx, "/1.0/instances?recursion=1", false)
		}
	}
	p, e := systemTool(name)
	if e != nil {
		return nil, e
	}
	if name == "incus" {
		// The provisioning capability is scoped to this authenticated host.
		// A user's default remote and first-run hints must never select another
		// daemon or contaminate its machine-readable local response.
		args = append([]string{"--force-local"}, args...)
	}
	c := exec.Command(p, args...)
	c.ExtraFiles = files
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "UCF_FORCE_CONFFOLD=1"}
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Output is bounded and never placed in heartbeat/logs (mirrors may be private).
	var out limitedBuffer
	var diagnostics limitedBuffer
	c.Stdout = &out
	c.Stderr = &out
	if name == "incus" || name == "apk" && len(args) > 0 && args[0] == "info" {
		c.Stderr = &diagnostics
	}
	if name == "rc-service" && len(args) == 2 && args[0] == "incudal-clock" && (args[1] == "restart" || args[1] == "start") {
		e = waitHostCommandWithService(ctx, c, verifiedManagedClockGroup)
	} else {
		e = waitHostCommand(ctx, c)
	}
	if out.overflow || diagnostics.overflow {
		return nil, fmt.Errorf("host command output exceeded limit")
	}
	// Some packaged tools deliberately return 1 with valid version output.
	// Preserve bounded bytes with that exit status so the caller can validate
	// the exact expected output; never turn exit!=0 into generic success.
	return out.data, e
}

func waitHostCommand(ctx context.Context, c *exec.Cmd) error {
	return waitHostCommandWithService(ctx, c, nil)
}

func waitHostCommandWithService(ctx context.Context, c *exec.Cmd, verify func(context.Context, int) bool) error {
	// OpenRC legitimately forks a service into its own session. Close inherited
	// output pipes after the command exits instead of waiting forever for that
	// daemon; never kill the newly started service's separate process group.
	c.WaitDelay = time.Second
	if err := c.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		live, groupErr := liveHostCommandGroup(ctx, "/proc", c.Process.Pid)
		if groupErr != nil {
			return groupErr
		}
		if live {
			if (err == nil || errors.Is(err, exec.ErrWaitDelay)) && verify != nil && verify(ctx, c.Process.Pid) {
				return nil
			}
			if verify != nil {
				return fmt.Errorf("host service process verification pending")
			}
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			if err == nil || errors.Is(err, exec.ErrWaitDelay) {
				return fmt.Errorf("host command child process remained in original group")
			}
		}
		if errors.Is(err, exec.ErrWaitDelay) {
			return nil // original command exited successfully; later state is verified
		}
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		_ = c.Process.Kill()
		<-done
		return ctx.Err()
	}
}

func liveHostCommandGroup(ctx context.Context, proc string, group int) (bool, error) {
	entries, err := os.ReadDir(proc)
	if err != nil || len(entries) > 65536 {
		return false, fmt.Errorf("host command process inventory unavailable")
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if proc == "/proc" {
			// Most processes are unrelated to this newly created command group.
			// Query the kernel group first; a disappearing or unreadable foreign
			// proc entry cannot poison an otherwise successful command receipt.
			pgid, groupErr := syscall.Getpgid(pid)
			if errors.Is(groupErr, syscall.ESRCH) {
				continue
			}
			if groupErr != nil {
				return false, fmt.Errorf("host command process group unavailable")
			}
			if pgid != group {
				continue
			}
		}
		data, err := os.ReadFile(filepath.Join(proc, entry.Name(), "stat"))
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil || len(data) > 8192 {
			return false, fmt.Errorf("host command process status unavailable")
		}
		end := strings.LastIndex(string(data), ") ")
		if end < 0 {
			return false, fmt.Errorf("host command process status invalid")
		}
		fields := strings.Fields(string(data[end+2:]))
		if len(fields) < 3 {
			return false, fmt.Errorf("host command process status invalid")
		}
		pgid, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, fmt.Errorf("host command process group invalid")
		}
		// kill(-pgid,0) includes already-exited zombies retained by Docker
		// PID 1. They run no code, hold no locks or pipes and need no kill.
		if pgid == group && fields[0] != "Z" && fields[0] != "X" {
			return true, nil
		}
	}
	return false, nil
}

type limitedBuffer struct {
	data     []byte
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.data)+n > 1048576 {
		b.overflow = true
	}
	if len(b.data) < 1048576 {
		left := 1048576 - len(b.data)
		if n > left {
			p = p[:left]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func check(ctx context.Context) error {
	if _, e := systemTool("lxcfs"); e != nil {
		return e
	}
	// Dynamic-library/executable failures must not mint readiness from file presence.
	for _, n := range required {
		if e := checkTool(ctx, n); e != nil {
			return fmt.Errorf("host tool %s execution failed", n)
		}
	}
	return nil
}

func checkTool(ctx context.Context, name string) error {
	if _, err := systemTool(name); err != nil {
		return err
	}
	flag := "--help"
	if name == "unsquashfs" {
		flag = "-version"
	}
	out, err := run(ctx, name, flag)
	var exit *exec.ExitError
	if name == "unsquashfs" && errors.As(err, &exit) && exit.ExitCode() == 1 && regexp.MustCompile(`(?m)^unsquashfs version [0-9]+\.[0-9]+`).Match(out) {
		return nil
	}
	if name == "btrfstune" && errors.As(err, &exit) && exit.ExitCode() == 1 && strings.Contains(string(out), "btrfstune [options]") {
		return nil
	}
	return err
}

func ensureDiskSupport(ctx context.Context) error {
	for _, module := range []string{"btrfs", "dm_thin_pool"} {
		if _, err := os.Stat("/sys/module/" + module); err != nil {
			if _, err = run(ctx, "modprobe", module); err != nil {
				return err
			}
		}
	}
	return nil
}
func lock() (func(), error) {
	dir := "/var/lib/incudal-agent"
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	for p := dir; p != "/"; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&0022 != 0 {
			return nil, fmt.Errorf("unsafe tool repair directory")
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return nil, fmt.Errorf("unsafe owner")
		}
	}
	fd, e := syscall.Open(dir+"/provisioning-tools.lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "tools-lock")
	i, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	st, owned := i.Sys().(*syscall.Stat_t)
	if !owned || st.Uid != 0 || st.Nlink != 1 || !i.Mode().IsRegular() || i.Mode()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("unsafe tool lock")
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
}

var apkChange = regexp.MustCompile(`(?m)(Installing|Upgrading|Downgrading|Reinstalling) ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*)\)`)
var aptChange = regexp.MustCompile(`(?m)^Inst ([a-zA-Z0-9+_.:-]+)([^\n]*)`)
var aptRemove = regexp.MustCompile(`(?m)^Remv `)
var aptVersion = regexp.MustCompile(`(?m)^Inst ([a-zA-Z0-9+_.:-]+)(?: \[[^\]]+\])? \(([0-9][a-zA-Z0-9+_.:~-]*) `)

func safePlan(output string, alpine bool) error {
	if strings.Contains(output, "Purging ") || strings.Contains(output, "Removing ") || strings.Contains(output, "Downgrading ") || strings.Contains(output, "UNTRUSTED") || aptRemove.MatchString(output) {
		return fmt.Errorf("package removal refused")
	}
	allowed := map[string]bool{"apparmor": true, "apparmor-utils": true, "libapparmor": true, "py3-apparmor": true, "py3-libapparmor": true, "perl": true, "tar": true, "gzip": true, "xz": true, "xz-utils": true, "squashfs-tools": true, "rsync": true, "lxcfs": true, "lxcfs-openrc": true, "util-linux": true, "util-linux-misc": true}
	for _, name := range []string{"lvm2", "lvm2-extra", "device-mapper", "thin-provisioning-tools", "btrfs-progs", "btrfs-progs-extra"} {
		allowed[name] = true
	}
	if alpine {
		for _, m := range securityPackageVersionChange.FindAllStringSubmatch(output, -1) {
			if !allowed[m[1]] {
				return fmt.Errorf("unrelated installed package %s change refused", m[1])
			}
		}
		if strings.Count(output, "Upgrading ") != len(securityPackageVersionChange.FindAllStringSubmatch(output, -1))+len(regexp.MustCompile(`(?m)Upgrading [a-zA-Z0-9+_.-]+ \([0-9][a-zA-Z0-9+_.~-]*\)`).FindAllString(output, -1)) {
			return fmt.Errorf("tool package upgrade plan invalid")
		}
		for _, m := range apkChange.FindAllStringSubmatch(output, -1) {
			if m[1] != "Installing" && !allowed[m[2]] {
				return fmt.Errorf("unrelated installed package %s change refused", m[2])
			}
		}
	} else {
		for _, m := range aptChange.FindAllStringSubmatch(output, -1) {
			if strings.HasPrefix(strings.TrimSpace(m[2]), "[") && !allowed[strings.Split(m[1], ":")[0]] {
				return fmt.Errorf("unrelated installed package %s change refused", m[1])
			}
		}
	}
	return nil
}
func repair(ctx context.Context) error {
	if e := check(ctx); e == nil {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("tool repair requires root")
	}
	unlock, e := lock()
	if e != nil {
		return e
	}
	defer unlock()
	release, e := releaseFile()
	if e != nil {
		return e
	}
	packages, e := packagesFor(release)
	if e != nil {
		return e
	}
	alpine := strings.Contains(release, "ID=alpine") || strings.Contains(release, "ID=\"alpine\"")
	// Reinstall only packages owning an actually missing/broken executable.
	// Reinstalling every tool for one missing aa-exec also runs LXCFS/LVM
	// maintainer hooks, which may disrupt otherwise healthy customer mounts.
	broken := []string{}
	for _, name := range append([]string{"lxcfs"}, required...) {
		var err error
		if name == "lxcfs" {
			_, err = systemTool(name)
		} else {
			err = checkTool(ctx, name)
		}
		if err != nil {
			broken = append(broken, name)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	packages = brokenToolPackages(broken, alpine)
	if len(packages) == 0 {
		return check(ctx)
	}
	if alpine {
		if e = repairAlpineTools(ctx, packages); e != nil {
			return e
		}
	} else {
		prefix := []string{"-o", "DPkg::Lock::Timeout=5", "-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowWeakRepositories=false", "-o", "Acquire::Retries=1", "-o", "Acquire::http::Timeout=10", "-o", "Acquire::https::Timeout=10"}
		// Pin already installed tools to their exact version. --no-upgrade
		// makes apt skip them even with --reinstall, so cannot heal lost files.
		requested := []string{}
		for _, name := range packages {
			installed, err := run(ctx, "dpkg-query", "-W", "-f=${Version}", name)
			version := strings.TrimSpace(string(installed))
			if err == nil && regexp.MustCompile(`^[0-9][a-zA-Z0-9+_.:~-]*$`).MatchString(version) {
				requested = append(requested, name+"="+version)
			} else {
				requested = append(requested, name)
			}
		}
		args := append(append([]string{}, prefix...), "--simulate", "install", "--reinstall", "--no-remove", "--no-install-recommends")
		args = append(args, requested...)
		out, e := run(ctx, "apt-get", args...)
		if e != nil {
			if _, e = run(ctx, "apt-get", append(append([]string{}, prefix...), "update", "-qq")...); e != nil {
				return e
			}
			out, e = run(ctx, "apt-get", args...)
		}
		if e != nil {
			return e
		}
		if e = safePlan(string(out), false); e != nil {
			return e
		}
		before, err := debianToolInventory(ctx)
		if err != nil {
			return err
		}
		expected, err := expectedDebianTools(before, string(out))
		if err != nil {
			return err
		}
		pinned := []string{}
		for _, change := range aptVersion.FindAllStringSubmatch(string(out), -1) {
			pinned = append(pinned, change[1]+"="+change[2])
		}
		if len(pinned) == 0 {
			return fmt.Errorf("tool repair plan unavailable")
		}
		actualPlan, err := run(ctx, "apt-get", append(append([]string{}, prefix...), append([]string{"--simulate", "install", "--reinstall", "--no-remove", "--no-install-recommends"}, pinned...)...)...)
		if err != nil {
			return err
		}
		actualExpected, err := expectedDebianTools(before, string(actualPlan))
		if err != nil || !reflect.DeepEqual(expected, actualExpected) {
			return fmt.Errorf("tool package pinned plan changed")
		}
		current, err := debianToolInventory(ctx)
		if err != nil || !reflect.DeepEqual(current, before) {
			return fmt.Errorf("tool package baseline changed")
		}
		args = append(append([]string{}, prefix...), "install", "-y", "--reinstall", "--no-remove", "--no-install-recommends")
		args = append(args, pinned...)
		if _, e = run(ctx, "apt-get", args...); e != nil {
			return e
		}
		after, err := debianToolInventory(ctx)
		if err != nil || !reflect.DeepEqual(after, expected) {
			return fmt.Errorf("tool package complete installation not confirmed")
		}
	}
	return check(ctx)
}
