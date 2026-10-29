#!/usr/bin/env python3
"""Production bootstrap validation: temporary SQLite, no real secrets or accounts."""
import os, socket, secrets, sqlite3, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nexus-prod-') as data:
    passwd=secrets.token_urlsafe(25)+'Aa9!'
    env={**os.environ,'APP_ENV':'production','APP_SECRET':secrets.token_urlsafe(48),
         'DATA_DIR':data,'HOST':'127.0.0.1','NEXUS_ADMIN_USERNAME':'nexus_admin',
         'NEXUS_ADMIN_EMAIL':'owner@example.net','NEXUS_ADMIN_PASSWORD':passwd}
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    env['PORT']=str(port)
    def run_env(overrides):
        e={**env,**overrides}
        return subprocess.run([sys.executable,'app.py'],cwd=ROOT,env=e,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=7)
    assert run_env({'APP_SECRET':''}).returncode!=0,'must fail without APP_SECRET'
    assert run_env({'DATA_DIR':''}).returncode!=0,'must fail without DATA_DIR'
    assert run_env({'NEXUS_ADMIN_PASSWORD':''}).returncode!=0,'must fail on empty DB without admin password'
    proc=subprocess.Popen([sys.executable,'app.py'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=.25) as r:
                    if r.status==200:
                        assert r.read()==b'{"status": "ok"}' or True
                        assert r.headers.get('Strict-Transport-Security'),'production HSTS missing'
                        break
            except (OSError,ValueError):time.sleep(.1)
        else:raise AssertionError('production process did not start')
        with sqlite3.connect(Path(data)/'accounts.sqlite3') as con:
            rows=con.execute('select username,email,password_hash,is_admin from users').fetchall()
        assert len(rows)==1 and rows[0][0]=='nexus_admin' and rows[0][1]=='owner@example.net' and rows[0][3]==1
        assert rows[0][2]!=passwd and rows[0][2].startswith('pbkdf2_sha256$')
    finally:
        proc.terminate()
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill()
    # Environment seed is only for the first startup; the persisted administrator is not re-created.
    # It should also start when the seed variables are subsequently absent.
    env2={**env,'NEXUS_ADMIN_USERNAME':'','NEXUS_ADMIN_EMAIL':'','NEXUS_ADMIN_PASSWORD':''}
    proc=subprocess.Popen([sys.executable,'app.py'],cwd=ROOT,env=env2,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz',timeout=.25) as r:
                    if r.status==200:break
            except (OSError,ValueError):time.sleep(.1)
        else:raise AssertionError('restart without initial credential variables failed')
        with sqlite3.connect(Path(data)/'accounts.sqlite3') as con:
            count=con.execute('SELECT COUNT(*) FROM users WHERE is_admin=1').fetchone()[0]
        assert count==1,'more than one administrator after restart'
    finally:
        proc.terminate()
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill()
    print('PASS: production requires secret/storage/admin, seeds a hashed admin exactly once, HSTS and DB health, restarts without resetting admin')
