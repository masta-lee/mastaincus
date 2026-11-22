"""Pinned post-7.6 crypto module fixes; preserve upstream's vendored build."""
import hashlib,pathlib,urllib.request,urllib.error,zipfile,io,shutil,re,ssl,time
MODULES={
 'crypto':('v0.59.0','b5cff645013a39d6b3348dce3c53eb452de71309f9a6831c5b12b3f8d6caf1d2'),
 'sys':('v0.50.0','b115e8a144a7c9d1df3ffb8af20b283e162844b5b624a97ee342955cca69b9e6'),
 'term':('v0.48.0','3f6dfe1b6031005d556ad54027c191636299aa4496fd631d1b1dcd23ada8bec7'),
 'text':('v0.44.0','e51c60a7d121a493048b1638023983ce183bd5d70df1db495423ce1415663202')
}
def download(url,limit):
 # Retry transient outages at most three times; preserve TLS and fixed hashes.
 for attempt in range(3):
  try:
   with urllib.request.urlopen(url,timeout=30)as response:raw=response.read(limit+1)
   if len(raw)>limit:raise ValueError('INCUS_SECURITY_MODULE_DOWNLOAD_TOO_LARGE')
   return raw
  except urllib.error.HTTPError as error:
   if error.code not in [408,429,500,502,503,504]or attempt==2:raise
  except urllib.error.URLError as error:
   if isinstance(error.reason,ssl.SSLCertVerificationError)or not isinstance(error.reason,(TimeoutError,ConnectionError))or attempt==2:raise
  except (TimeoutError,ConnectionError):
   if attempt==2:raise
  time.sleep(attempt+1)

def update(source):
 source=pathlib.Path(source);manifest=source/'vendor/modules.txt';text=manifest.read_text();mod=source/'go.mod'
 for name,(version,checksum) in MODULES.items():
  raw=download('https://proxy.golang.org/golang.org/x/'+name+'/@v/'+version+'.zip',32*1024*1024)
  if hashlib.sha256(raw).hexdigest()!=checksum:raise ValueError('INCUS_SECURITY_MODULE_CHECKSUM_INVALID')
  prefix='golang.org/x/'+name+'@'+version+'/'
  destination=source/'vendor/golang.org/x'/name
  if destination.is_symlink():raise ValueError('INCUS_SECURITY_MODULE_PATH_INVALID')
  # Only this pinned module tree in the disposable build workspace is replaced.
  if destination.exists():shutil.rmtree(destination)
  with zipfile.ZipFile(io.BytesIO(raw))as archive:
   for path in archive.namelist():
    if not path.startswith(prefix):raise ValueError('INCUS_SECURITY_MODULE_PATH_INVALID')
    relative=path[len(prefix):]
    if not relative or path.endswith('/')or relative.endswith('_test.go'):continue
    if '..'in pathlib.PurePosixPath(relative).parts:raise ValueError('INCUS_SECURITY_MODULE_PATH_INVALID')
    target=destination/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(path))
  text=re.sub(r'(# golang.org/x/'+name+r') v[^\n]+',r'\g<1> '+version,text)
  # Retain go.sum's verified module identities even though builds use vendor.
  sums=download('https://sum.golang.org/lookup/golang.org/x/'+name+'@'+version,65536).decode().splitlines()
  values=[line for line in sums if line.startswith('golang.org/x/'+name+' '+version)]
  if len(values)!=2 or any(not re.fullmatch(r'golang.org/x/'+name+r' '+re.escape(version)+r'(?:/go.mod)? h1:[A-Za-z0-9+/]{43}=',line)for line in values):raise ValueError('INCUS_SECURITY_MODULE_SUM_INVALID')
  with (source/'go.sum').open('a')as stream:stream.write('\n'+'\n'.join(values)+'\n')
  content=mod.read_text();content=re.sub(r'(golang.org/x/'+name+r') v[^\s]+',r'\g<1> '+version,content);mod.write_text(content)
 manifest.write_text(text)
 # GoBGP's OSV range has no fixed version. 7.6 already includes the exact
 # official recv-loop fix; retain this assertion instead of muting the finding.
 bgp=(source/'vendor/github.com/osrg/gobgp/v4/pkg/server/fsm.go').read_text()
 if not re.search(r'if handling == bgp.ERROR_HANDLING_NONE\s*\{\s*ok, \w+ := bgp.ValidateUpdateMsg',bgp):raise ValueError('INCUS_BGP_SECURITY_FIX_MISSING')
