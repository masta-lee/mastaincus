"""Real root permissions for a flat install with an existing releases folder."""
import os,pathlib,subprocess,tempfile,unittest
if hasattr(os,'geteuid'):import pwd

@unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'disposable Linux root required')
class Ownership(unittest.TestCase):
 def test_flat_active_code_is_hardened_with_releases(self):
  source=(pathlib.Path(__file__).resolve().parent.parent/'deploy/incudal-online-task.sh.example').read_text()
  start=source.index('apply_secure_ownership() {');end=source.index('\nverify_git_control() {',start)
  body=source[start:end]
  with tempfile.TemporaryDirectory(prefix='incudal-flat-ownership-')as directory:
   root=pathlib.Path(directory);account=pwd.getpwnam('nobody');group=__import__('grp').getgrgid(account.pw_gid).gr_name
   for name in ['app/server/certs','app/releases','app/.cache','helpers/ota-path','manifests','cache']:(root/name).mkdir(parents=True,exist_ok=True)
   for name in ['app/server/code.js','app/server/certs/client.key','app/.cache/data']:
    path=root/name;path.write_text('synthetic-only');os.chown(path,account.pw_uid,account.pw_gid);path.chmod(0o600)
   for name in ['incudal-online-task','systemctl','ota-path/chown']:(root/'helpers'/name).write_text('#!/bin/sh\nexit 0\n')
   script='set -euo pipefail\nINSTALL_DIR='+str(root/'app')+'\nRUN_USER='+account.pw_name+'\nRUN_GROUP='+group+'\nHELPER_DIR='+str(root/'helpers')+'\nMANIFEST_DIR='+str(root/'manifests')+'\nROOT_CACHE_DIR='+str(root/'cache')+'\nresolve_app_dir(){ printf "%s\\n" "$INSTALL_DIR"; }\n'+body+'\napply_secure_ownership\n'
   subprocess.run(['/usr/bin/bash','-c',script],check=True)
   for name in ['app/server/code.js','app/server/certs/client.key']:
    self.assertEqual((root/name).stat().st_uid,0);self.assertEqual((root/name).stat().st_mode&0o022,0)
   self.assertEqual((root/'app/.cache/data').stat().st_uid,account.pw_uid)

if __name__=='__main__':unittest.main()
