import importlib.util,pathlib,unittest
spec=importlib.util.spec_from_file_location('nginx_security',pathlib.Path(__file__).with_name('harden-nginx-logging.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Config(unittest.TestCase):
    def test_target_only(self):
        other='server {\n root /srv/other;\n access_log /var/log/nginx/other.log;\n}'
        target='server {\n root /opt/incudal/current/client/dist/user;\n location /api {\n access_log /var/log/nginx/access.log;\n error_log /var/log/nginx/error.log;\n proxy_pass http://127.0.0.1:3001;\n }\n}'
        result=module.harden(target+'\n'+other)
        self.assertIn(other,result);self.assertNotIn('nginx/access.log',result);self.assertNotIn('nginx/error.log',result)
        self.assertIn('proxy_pass http://127.0.0.1:3001;',result)
        self.assertEqual(module.harden(result),result)
if __name__=='__main__':unittest.main()
