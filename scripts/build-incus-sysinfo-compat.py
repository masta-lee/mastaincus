#!/usr/bin/env python3
"""Build the security baseline Alpine Incus 7.6.0 daemon from pinned official sources."""
import hashlib, json, os, pathlib, subprocess, tarfile, urllib.request

SOURCE_SHA = 'f57dcf2b781f6664b04b264e680d6b05a86303bbee717161110282e2a8891486'
SOURCE_URL = 'https://github.com/lxc/incus/releases/download/v7.6.0/incus-7.6.0.tar.gz'
root = pathlib.Path('/build/incus-sysinfo')
root.mkdir(parents=True, exist_ok=True)
archive = root / 'source.tar.gz'
if not archive.exists():
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
        archive.write_bytes(response.read())
assert hashlib.sha256(archive.read_bytes()).hexdigest() == SOURCE_SHA
with tarfile.open(archive) as tar:
    tar.extractall(root, filter='data')
source = root / 'incus-7.6'
import sys
sys.path.insert(0,'/')
from incus_security_modules import update as update_security_modules, MODULES as security_modules
update_security_modules(source)
target = source / 'cmd/incusd/dev_incus.go'
text = target.read_text()
marker = 'func findContainerForPid(pid int32, s *state.State) (instance.Container, error) {'
assert text.count(marker) == 1
helper = '''// Backport upstream monitor identification (5daa427d), anchored as in
// upstream security fix 83eaa5e1. Customer-created descendant names are ignored.
func incudalContainerNameFromCgroup(content string) (string, bool) {
    for _, line := range strings.Split(content, "\\n") {
        _, path, found := strings.Cut(line, ":/")
        if !found { continue }
        for _, component := range strings.Split(path, "/") {
            for _, prefix := range []string{"lxc.payload.", "lxc.monitor."} {
                if strings.HasPrefix(component, prefix) && len(component)>len(prefix) {
                    return component[len(prefix):], true
                }
            }
        }
    }
    return "", false
}

'''
text = text.replace(marker, helper + marker)
insert = '\t\tre, err := regexp.Compile(`^PPid:\\s+([0-9]+)$`)'
assert text.count(insert) == 1
code = '''        // Alpine's monitor argv is empty on affected builds. Use the
        // original kernel cgroup before the PID namespace fallback.
        cgroup, cgroupErr := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
        if cgroupErr == nil {
            if name, found := incudalContainerNameFromCgroup(string(cgroup)); found {
                projectName := api.ProjectDefaultName
                if strings.Contains(name, "_") {
                    fields := strings.SplitN(name, "_", 2)
                    projectName, name = fields[0], fields[1]
                }
                inst, loadErr := instance.LoadByProjectAndName(s, projectName, name)
                if loadErr != nil { return nil, loadErr }
                container, ok := inst.(instance.Container)
                if !ok { return nil, errors.New("Instance is not container type") }
                return container, nil
            }
        }

'''
text = text.replace(insert, code + insert)
target.write_text(text)
lxc_target = source / 'internal/server/instance/drivers/driver_lxc.go'
lxc_text = lxc_target.read_text()
lxc_marker = '''func (d *lxc) Rebuild(img *api.Image, op *operations.Operation) error {
	return d.rebuildCommon(d, img, op)
}'''
assert lxc_text.count(lxc_marker) == 1
lxc_text = lxc_text.replace(lxc_marker, '''func (d *lxc) Rebuild(img *api.Image, op *operations.Operation) error {
    // Replacing a stopped root filesystem must exclude SFTP mounts and other
    // lifecycle actions. FileSFTPConn already waits on this operation lane.
    rebuildLock, err := operationlock.CreateWaitGet(d.Project().Name, d.Name(), op, operationlock.ActionRestore, nil, false, false)
    if err != nil { return err }
    defer rebuildLock.Done(nil)
    if d.IsRunning() { return errors.New("Instance must be stopped to be rebuilt") }
    d.stopForkfile(false)
    // A failed rebuild can already have removed the storage volume row.
    // Resolve the original configured root pool before the common path tries
    // to look it up through that deleted volume record.
    _, rootDisk, err := d.getRootDiskDevice()
    if err != nil || rootDisk["pool"] == "" { return errors.New("Rebuild root storage pool unavailable") }
    d.storagePool, err = storagePools.LoadByName(d.state, rootDisk["pool"])
    if err != nil { return err }
    return d.rebuildCommon(d, img, op)
}''')
backup_marker = '''	// Write the current instance state to backup file.
	pool, err := d.getStoragePool()
	if err != nil {
		return err
	}'''
assert lxc_text.count(backup_marker) == 1
lxc_text = lxc_text.replace(backup_marker, '''	// Write the current instance state to backup file.
	pool, err := d.getStoragePool()
	if err != nil {
        // Failed rebuilds can remove both the volume row and instance link.
        // Update already permits an absent backup file for a stopped rootfs;
        // classify only that exact absence so pre-rebuild config can persist.
        // An existing link, running guest, or other pool error is not ignored.
        if !d.IsRunning() && !d.IsSnapshot() && api.StatusErrorCheck(err, http.StatusNotFound) {
            _, pathErr := os.Lstat(d.Path())
            if errors.Is(pathErr, fs.ErrNotExist) { return fs.ErrNotExist }
        }
		return err
	}''')
lxc_target.write_text(lxc_text)
btrfs_target = source / 'internal/server/storage/drivers/driver_btrfs_volumes.go'
btrfs_text = btrfs_target.read_text()
assert '\t"syscall"\n' not in btrfs_text
btrfs_text = btrfs_text.replace('\t"strings"\n', '\t"strings"\n\t"syscall"\n')
btrfs_marker = '''	target := vol.MountPath()

	// Recursively copy the main volume.'''
assert btrfs_text.count(btrfs_marker) == 1
btrfs_text = btrfs_text.replace(btrfs_marker, '''    target := vol.MountPath()
    mountUnlock, err := vol.MountLock()
    if err != nil { return err }
    defer mountUnlock()
    if vol.MountInUse() { return ErrInUse }
    // Recover an empty ordinary mount directory from an interrupted rebuild.
    // A real subvolume (inode 256), symlink, or nonempty directory is never
    // removed. rmdir is nonrecursive and fails closed if another writer wins.
    if info, statErr := os.Lstat(target); statErr == nil {
        stat, ok := info.Sys().(*syscall.Stat_t)
        if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Ino == 256 {
            return fmt.Errorf("Target volume already exists: %q", target)
        }
        if err = os.Remove(target); err != nil { return fmt.Errorf("Target mount directory is not empty: %w", err) }
    } else if !os.IsNotExist(statErr) { return statErr }

    // Recursively copy the main volume.''')
delete_marker = '''	// Delete the volume (and any subvolumes).
	err = d.deleteSubvolume(volPath, true)'''
assert btrfs_text.count(delete_marker) == 1
btrfs_text = btrfs_text.replace(delete_marker, '''    // An interrupted root replacement may have left only an empty ordinary
    // mount directory, not a Btrfs subvolume. Remove that exact empty directory
    // under its mount lock; never recurse into unconfirmed data.
    mountUnlock, err := vol.MountLock()
    if err != nil { return err }
    defer mountUnlock()
    if vol.MountInUse() { return ErrInUse }
    info, err := os.Lstat(volPath)
    if err != nil { return err }
    stat, ok := info.Sys().(*syscall.Stat_t)
    if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok {
        return fmt.Errorf("Invalid volume path: %q", volPath)
    }
    if stat.Ino != 256 {
        if err = os.Remove(volPath); err != nil { return fmt.Errorf("Unconfirmed volume directory is not empty: %w", err) }
        return deleteParentSnapshotDirIfEmpty(d.name, vol.volType, volName)
    }
	// Delete the volume (and any subvolumes).
	err = d.deleteSubvolume(volPath, true)''')
btrfs_target.write_text(btrfs_text)
(source / 'cmd/incusd/incudal_monitor_test.go').write_text('''package main
import "testing"
func TestIncudalMonitorCgroup(t *testing.T) {
 for _, tc:=range []struct{input,want string}{
  {"0::/lxc.monitor.guest\\n","guest"},
  {"0::/lxc.payload.original/lxc.monitor.other\\n","original"},
  {"0::/system.slice/lxc.monitor.guest/child\\n","guest"},
  {"0::/user.slice/not-lxc.monitor.fake\\n",""},
  {"malformed",""},
 } { got,ok:=incudalContainerNameFromCgroup(tc.input);if got!=tc.want||ok!=(tc.want!=""){t.Fatal(tc.input,got)} }
}
''')
subprocess.run(['gofmt','-w',str(target),str(lxc_target),str(btrfs_target),str(source/'cmd/incusd/incudal_monitor_test.go')],check=True)

# Only the daemon run entry applies the memory defaults. Fork helpers restore
# the native policy before customer namespace entry; environment is unchanged.
memory_target=source/'cmd/incusd/incudal_memory.go'
memory_target.write_bytes(pathlib.Path('/incus-memory-default.go').read_bytes())
native_memory_target=source/'cmd/incusd/incudal_native_memory.go'
native_memory_target.write_bytes(pathlib.Path('/incus-native-memory.go').read_bytes())
(source/'cmd/incusd/incudal_memory_test.go').write_bytes(pathlib.Path('/incus-memory-default_test.go').read_bytes())
daemon_target=source/'cmd/incusd/main_daemon.go'
daemon_text=daemon_target.read_text()
memory_marker='\tneededPrograms := []string{"ip", "rsync", "setfattr", "tar", "unsquashfs", "xz"}'
assert daemon_text.count(memory_marker)==1
daemon_target.write_text(daemon_text.replace(memory_marker,'\tincudalNativeMemoryDefault()\n\tincudalConfigureDaemonMemory()\n\n'+memory_marker))
# Reset mm THP inheritance in the original C constructor, before its forkexec
# and namespace code can enter a guest. All non-daemon helper commands reset,
# including Go-managed forklxc/forkqemu and callhook paths.
namespace_target=source/'cmd/incusd/main_nsexec.go'
namespace_text=namespace_target.read_text()
include='#include <sys/prctl.h>\n'
if include not in namespace_text: namespace_text=namespace_text.replace('#include <sys/stat.h>\n',include+'#include <sys/stat.h>\n')
constructor_marker='\t// Intercepts some subcommands'
assert namespace_text.count(constructor_marker)==1
namespace_text=namespace_text.replace(constructor_marker,'''    // Daemon-only small-host THP policy must never enter customer processes.
    // This executes before forkexec/forkfile namespace transitions.
    if (strcmp(cmdline_cur, "daemon") != 0 && prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) > 0) {
        if (prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) != 0) {
            fprintf(stderr, "Unable to restore helper THP policy\\n");
            _exit(233);
        }
    }

'''+constructor_marker)
namespace_target.write_text(namespace_text)
raft_memory_target=source/'internal/server/cluster/incudal_raft_memory.go'
raft_memory_target.write_bytes(pathlib.Path('/incus-raft-memory.go').read_bytes())
(source/'internal/server/cluster/incudal_raft_memory_test.go').write_bytes(pathlib.Path('/incus-raft-memory_test.go').read_bytes())
gateway_target=source/'vendor/github.com/cowsql/go-cowsql/cluster/gateway/gateway.go'
# Upstream 7.6 moves the gateway into the cowsql module. Keep its actual
# standalone creation path tuned; cluster behavior and formats stay upstream.
(gateway_target.parent/'incudal_raft_memory.go').write_text(raft_memory_target.read_text().replace('package cluster','package gateway',1))
gateway_text=gateway_target.read_text()
raft_marker='\t\t\tg.memoryDial = cowsqlMemoryDial(g.bindAddress)'
assert gateway_text.count(raft_marker)==1
gateway_target.write_text(gateway_text.replace(raft_marker,'''            // Only a standalone small host changes retention; cluster policy
            // and recovery formats remain the original cowsql defaults.
            if option := incudalStandaloneRaftOption(info.Address); option != nil {
                options = append(options, option)
            }
'''+raft_marker))
subprocess.run(['gofmt','-w',str(memory_target),str(native_memory_target),str(namespace_target),str(source/'cmd/incusd/incudal_memory_test.go'),str(daemon_target),str(raft_memory_target),str(gateway_target),str(source/'internal/server/cluster/incudal_raft_memory_test.go')],check=True)
env={**os.environ,'CGO_ENABLED':'1','CGO_CFLAGS':'-I/usr/include/raft -I/usr/include/cowsql','CGO_LDFLAGS':'-lintl','CGO_LDFLAGS_ALLOW':'(-Wl,-wrap,pthread_create)|(-Wl,-z,now)'}
subprocess.run(['go','test','-tags=libsqlite3','-run=^(TestIncudalMonitorCgroup|TestIncudalDaemonMemoryBudget)$','./cmd/incusd'],cwd=source,env=env,check=True)
subprocess.run(['go','test','-tags=libsqlite3','-run=^TestIncudalStandaloneRaftMemory$','./internal/server/cluster'],cwd=source,env=env,check=True)
output=pathlib.Path('/out');output.mkdir(exist_ok=True)
binary=output/'incusd'
defaults=subprocess.check_output(['go','list','-tags=libsqlite3','-f','{{.DefaultGODEBUG}}','./cmd/incusd'],cwd=source,env=env,text=True).strip()
defaults=','.join(filter(None,[defaults,'disablethp=1']))
subprocess.run(['go','build','-tags=libsqlite3','-trimpath','-buildvcs=false','-ldflags=-s -w -X runtime.godebugDefault='+defaults,'-o',str(binary),'./cmd/incusd'],cwd=source,env=env,check=True)
# trimpath intentionally omits link flags from build information. Verify the
# exact runtime flag on actual touched Go heap mappings, including override.
probe=output/'incus-memory-probe'
subprocess.run(['go','build','-trimpath','-ldflags=-X runtime.godebugDefault='+defaults,'-o',str(probe),'/test-incus-memory-runtime.go'],env=env,check=True)
subprocess.run([str(probe)],env={**env,'INCUDAL_EXPECT_SMALL_PAGES':'1'},check=True)
subprocess.run([str(probe)],env={**env,'GODEBUG':'disablethp=0','INCUDAL_EXPECT_SMALL_PAGES':'0'},check=True)
probe.unlink()
subprocess.run(['ldd',str(binary)],check=True)
manifest={'schemaVersion':1,'purpose':'alpine-incus-sysinfo-compat','incusVersion':'7.6.0','sourceUrl':SOURCE_URL,'sourceSha256':SOURCE_SHA,
 'upstreamFixes':['5daa427d330004609859ab6f19b6101d3479d59c','83eaa5e19345a4719df46bcdb2850547d069b88e'],
 'architecture':os.uname().machine,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'size':binary.stat().st_size,
 'patchedSourceSha256':hashlib.sha256(target.read_bytes()).hexdigest(),
 'lifecycleSourceSha256':hashlib.sha256(lxc_target.read_bytes()+btrfs_target.read_bytes()).hexdigest(),
 'memorySourceSha256':hashlib.sha256(memory_target.read_bytes()+native_memory_target.read_bytes()).hexdigest(),
 'memoryNamespaceSourceSha256':hashlib.sha256(namespace_target.read_bytes()).hexdigest(),
 'memoryRaftSourceSha256':hashlib.sha256(raft_memory_target.read_bytes()+gateway_target.read_bytes()).hexdigest(),
 'memoryBuildDefault':'disablethp=1', 'memoryBudgetRevision':'daemon-memory-v3',
 'securityModules':{name:{'version':value[0],'zipSha256':value[1]} for name,value in security_modules.items()},
 'securityModulesScriptSha256':hashlib.sha256(pathlib.Path('/incus_security_modules.py').read_bytes()).hexdigest()}
(output/'incusd-manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest))
