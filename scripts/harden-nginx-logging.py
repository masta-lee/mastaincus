#!/usr/bin/env python3
"""Tighten only installed PayIncus virtual hosts, preserving routing and TLS."""
import os,re,pathlib,subprocess,tempfile

def harden(text):
    starts=list(re.finditer(r'(?m)^\s*server\s*\{',text));edits=[]
    for match in starts:
        start=match.start();opened=text.index('{',match.start(),match.end());depth=1;position=opened+1
        # Generated nginx blocks use neither braces in quoted strings nor
        # arbitrary embedded code. Unsupported layouts stay unchanged.
        quote=None;comment=False
        while position<len(text) and depth:
            character=text[position]
            if comment:
                if character=='\n':comment=False
            elif quote:
                if character=='\\':position+=1
                elif character==quote:quote=None
            elif character in ['"',"'"]:quote=character
            elif character=='#':comment=True
            elif character=='{':depth+=1
            elif character=='}':depth-=1
            position+=1
        if depth:raise ValueError('NGINX_SECURITY_LAYOUT_UNSUPPORTED')
        block=text[start:position]
        if not re.search(r'(?m)^\s*root\s+/opt/incudal/(?:current/|releases/[A-Za-z0-9._-]+/)?client/dist/(?:user|admin)\s*;',block):continue
        # Override all per-location logging too; a more specific access/error
        # directive could otherwise re-enable bearer URL exposure.
        block=re.sub(r'(?m)^([ \t]*)access_log[ \t]+[^;\n]+;', r'\1access_log off;',block)
        block=re.sub(r'(?m)^([ \t]*)error_log[ \t]+[^;\n]+;', r'\1error_log /dev/null;',block)
        if '# PayIncus sensitive URL logging' not in block:
            head=block.index('{')+1
            block=block[:head]+'\n    # PayIncus sensitive URL logging\n    access_log off;\n    error_log /dev/null;'+block[head:]
        edits.append((start,position,block))
    for start,end,block in reversed(edits):text=text[:start]+block+text[end:]
    return text

def main():
    if os.geteuid()!=0:raise ValueError('NGINX_SECURITY_ROOT_REQUIRED')
    paths=[*pathlib.Path('/etc/nginx/sites-available').glob('*'),*pathlib.Path('/etc/nginx/conf.d').glob('*.conf')]
    saved=[]
    def replace(path,data):
        descriptor,name=tempfile.mkstemp(prefix='.incudal-nginx-',dir=path.parent)
        try:
            with os.fdopen(descriptor,'wb')as stream:os.fchmod(stream.fileno(),path.stat().st_mode&0o777);stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.replace(name,path)
        finally:
            if os.path.exists(name):os.unlink(name)
    try:
        for path in paths:
            if not path.is_file() or path.is_symlink():continue
            info=path.stat()
            if info.st_uid!=0 or info.st_mode&0o022 or info.st_size>1024*1024:raise ValueError('NGINX_SECURITY_CONFIG_UNTRUSTED')
            original=path.read_bytes();updated=harden(original.decode()).encode()
            if updated!=original:saved.append((path,original));replace(path,updated)
        if saved:
            subprocess.run(['nginx','-t'],capture_output=True,check=True,timeout=10)
            subprocess.run(['systemctl','reload','nginx'],capture_output=True,check=True,timeout=20)
    except Exception:
        for path,data in saved:replace(path,data)
        raise

if __name__=='__main__':main()
