"""Fixed-source download policy; no network or component mutation."""
import importlib.util,pathlib,unittest,io,urllib.error,ssl
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('modules',pathlib.Path(__file__).with_name('incus-security-modules.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Downloads(unittest.TestCase):
 def test_transient_then_success(self):
  with patch.object(module.urllib.request,'urlopen',side_effect=[urllib.error.URLError(TimeoutError()),io.BytesIO(b'fixed')])as call,patch.object(module.time,'sleep')as sleep:
   self.assertEqual(module.download('https://proxy.golang.org/fixed',5),b'fixed');self.assertEqual(call.call_count,2);sleep.assert_called_once_with(1)
 def test_transient_exhausted(self):
  with patch.object(module.urllib.request,'urlopen',side_effect=TimeoutError())as call,patch.object(module.time,'sleep'):
   with self.assertRaises(TimeoutError):module.download('https://proxy.golang.org/fixed',5)
   self.assertEqual(call.call_count,3)
 def test_certificate_never_retried(self):
  with patch.object(module.urllib.request,'urlopen',side_effect=urllib.error.URLError(ssl.SSLCertVerificationError()))as call:
   with self.assertRaises(urllib.error.URLError):module.download('https://proxy.golang.org/fixed',5)
   self.assertEqual(call.call_count,1)
 def test_oversize_and_client_error_never_retried(self):
  with patch.object(module.urllib.request,'urlopen',return_value=io.BytesIO(b'too large'))as call:
   with self.assertRaisesRegex(ValueError,'TOO_LARGE'):module.download('https://proxy.golang.org/fixed',5)
   self.assertEqual(call.call_count,1)
  with patch.object(module.urllib.request,'urlopen',side_effect=urllib.error.HTTPError('https://proxy.golang.org/fixed',404,'missing',{},None))as call:
   with self.assertRaises(urllib.error.HTTPError):module.download('https://proxy.golang.org/fixed',5)
   self.assertEqual(call.call_count,1)
if __name__=='__main__':unittest.main()
