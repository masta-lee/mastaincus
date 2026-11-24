#!/usr/bin/env python3
"""Real Bash sealed verification: locale order can change, bytes cannot."""
import pathlib,subprocess,tempfile,os
source=pathlib.Path(__file__).resolve().parents[1].joinpath('deploy/incudal-online-task.sh.example').read_text()
function=source[source.index('verify_manifest() {'):source.index('\nseal_release() {')]
with tempfile.TemporaryDirectory(prefix='payincus-seal-order-')as directory:
    root=pathlib.Path(directory);(root/'alpha').write_text('original');(root/'Beta').write_text('beta');(root/'link').symlink_to('alpha')
    manifest=root/'manifest';links=root/'manifest.links';manifest.write_text(subprocess.check_output(['sha256sum','./alpha','./Beta'],cwd=root,text=True));links.write_text('./link -> alpha\n')
    body='set -euo pipefail\nfail(){ echo "$*" >&2; exit 1; }\nresolve_app_dir(){ printf "%s" "$1"; }\n'
    body+='resolve_app_dir(){ printf "%s" '+repr(str(root))+'; }\nmanifest_path(){ printf "%s" '+repr(str(manifest))+'; }\nMANIFEST_DIR='+repr(str(root))+'\n'
    body+='static_files(){ printf "./Beta\\0./alpha\\0"; }\nstatic_links(){ printf "./link\\0"; }\nlink_entries(){ printf "./link -> alpha\\n"; }\n'+function+'\nverify_manifest\n'
    def run():return subprocess.run(['bash','-c',body],cwd=root,capture_output=True,text=True,timeout=5)
    assert run().returncode==0,'same complete file/link records reordered must verify'
    saved=manifest.read_text();manifest.write_text(saved+saved.splitlines()[0]+'\n');assert run().returncode!=0,'duplicate record rejected';manifest.write_text(saved)
    manifest.write_text('\n'.join(saved.splitlines()[:-1])+'\n');assert run().returncode!=0,'missing record rejected';manifest.write_text(saved)
    links.write_text('./link -> Beta\n');assert run().returncode!=0,'changed link rejected';links.write_text('./link -> alpha\n')
    (root/'alpha').write_text('changed');assert run().returncode!=0,'changed file bytes rejected'
print('PASS actual sealed Bash verification preserves full file/link integrity across record order')
