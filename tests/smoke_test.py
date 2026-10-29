#!/usr/bin/env python3
"""Local-only Nexus smoke tests. Creates temporary data; never modifies site accounts."""
import os, re, sys, time, socket, secrets, tempfile, subprocess, sqlite3
from pathlib import Path
from urllib.parse import urlparse
from http import HTTPStatus
import urllib.request, urllib.error, urllib.parse, http.cookiejar

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nexus-smoke-') as data:
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    passwd=secrets.token_urlsafe(30)+'Aa1!!'
    env=dict(os.environ,DATA_DIR=data,HOST='127.0.0.1',PORT=str(port),APP_ENV='development',
             APP_SECRET=secrets.token_urlsafe(48),NEXUS_ADMIN_USERNAME='nexus_admin',
             NEXUS_ADMIN_EMAIL='nexus-owner@example.org',NEXUS_ADMIN_PASSWORD=passwd)
    proc=subprocess.Popen([sys.executable,'app.py'],cwd=ROOT,env=env,
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def client():
        jar=http.cookiejar.CookieJar()
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        return opener
    anonymous=client(); admin=client(); user=client(); other=client()
    checks=[]
    def req(opener,path,form=None,method=None,headers=None):
        data=None if form is None else urllib.parse.urlencode(form).encode('utf8')
        request=urllib.request.Request(base+path,data=data,headers=headers or {},method=method or ('POST' if form is not None else 'GET'))
        try: r=opener.open(request,timeout=12)
        except urllib.error.HTTPError as e:r=e
        result=r.read().decode('utf8','replace')
        return r.status,result,r.geturl(),r.headers
    def csrf(page):
        m=re.search(r'<input[^>]*name="csrf"[^>]*>',page)
        assert m,'CSRF field missing'
        return re.search(r'value="([^"]+)"',m.group()).group(1)
    def login(opener,identifier,password):
        status,page,_,_=req(opener,'/login')
        assert status==200
        return req(opener,'/login',{'csrf':csrf(page),'identifier':identifier,'password':password})
    def signup(opener,name,email):
        status,page,_,_=req(opener,'/signup')
        assert status==200
        return req(opener,'/signup',{'csrf':csrf(page),'username':name,'email':email,'password':'GuestTest#1234','confirm_password':'GuestTest#1234'})
    def check(label,condition):
        assert condition,label
        checks.append(label)
    try:
        for _ in range(70):
            try:
                if req(anonymous,'/healthz')[0]==200:break
            except (OSError,ConnectionError):time.sleep(.1)
        else:raise RuntimeError('Server did not become healthy')
        check('healthz',req(anonymous,'/healthz')[0]==200)
        public=['/','/index.html','/intro','/intro.html','/features','/plans','/plans.html','/creator','/creator.html','/contact','/contact.html','/support','/login','/signup']
        for path in public:
            status,page,final,headers=req(anonymous,path)
            check('public '+path,status==200 and 'Nexus' in page and '/admin/change-password' not in page)
            check('content header '+path,headers.get('X-Content-Type-Options')=='nosniff')
        check('favicon',req(anonymous,'/favicon.png')[0]==200)
        check('robots',req(anonymous,'/robots.txt')[0]==200)
        check('creator discord', 'ceonag0698' in req(anonymous,'/creator.html')[1])
        check('unauthed admin redirected', '/login' in req(anonymous,'/admin/support')[2])
        check('unauthed admin api blocked',req(anonymous,'/api/admin/inquiries')[0]==401)
        for path in ['/app.py','/data/accounts.sqlite3','/.env','/README.md','/templates/admin.html']:
            check('private '+path,req(anonymous,path)[0]==404)
        status,page,final,headers=login(admin,'nexus_admin',passwd)
        check('admin login',status==200 and '/account' in final)
        for path in ['dashboard','content','plans','members','support']:
            status,page,final,headers=req(admin,'/admin/'+path)
            check('admin '+path,status==200 and '관리 카테고리' in page and '403 접근 권한' not in page)
        status,page,final,headers=signup(user,'nexus_test_customer','nexus_customer@example.org')
        check('member signup',status==200 and '/account' in final)
        check('member admin 403',req(user,'/admin/dashboard')[0]==403)
        check('member admin api 403',req(user,'/api/admin/inquiries')[0]==403)
        status,page,final,headers=signup(other,'nexus_other','nexus_other@example.org')
        check('second member',status==200 and '/account' in final)
        status,page,final,headers=req(user,'/contact.html')
        status,page,final,headers=req(user,'/inquiries/start',{'csrf':csrf(page),'category':'general'})
        match=re.search(r'/inquiries/(\d+)',final)
        check('create ticket',status==200 and match is not None)
        ticket=int(match.group(1))
        status,page,_,_=req(user,f'/inquiries/{ticket}')
        check('chat page',status==200)
        status,page,_,_=req(user,f'/inquiries/{ticket}/send',{'csrf':csrf(page),'body':'고객지원 메시지 테스트'})
        check('message accepted',status==200)
        import json
        unread=json.loads(req(admin,'/api/admin/inquiries/unread')[1])['unread']
        check('unread increases',unread==1)
        check('other user denied chat',req(other,f'/inquiries/{ticket}')[0]==404)
        check('other user denied chat api',req(other,f'/api/inquiries/{ticket}/messages')[0]==404)
        status,page,_,_=req(admin,f'/inquiries/{ticket}')
        check('admin sees customer message','고객지원 메시지 테스트' in page)
        check('unread decreases',json.loads(req(admin,'/api/admin/inquiries/unread')[1])['unread']==0)
        status,page,_,_=req(admin,f'/inquiries/{ticket}/send',{'csrf':csrf(page),'body':'관리자 정상 답변'})
        check('admin sends message',status==200)
        check('customer sees admin response','관리자 정상 답변' in req(user,f'/inquiries/{ticket}')[1])
        status,page,_,_=req(admin,f'/inquiries/{ticket}')
        status,page,_,_=req(admin,f'/admin/inquiries/{ticket}/status',{'csrf':csrf(page),'status':'closed'})
        check('close ticket',status==200 and '상담 종료' in page)
        status,page,_,_=req(user,f'/inquiries/{ticket}')
        check('closed chat notice','종료된 상담입니다' in page)
        check('send to closed denied',req(user,f'/inquiries/{ticket}/send',{'csrf':csrf(page),'body':'should reject'})[0]==409)
        status,page,_,_=req(admin,f'/inquiries/{ticket}')
        status,page,_,_=req(admin,f'/admin/inquiries/{ticket}/status',{'csrf':csrf(page),'status':'open'})
        check('reopen ticket',status==200 and '상담 중' in page)
        with sqlite3.connect(Path(data)/'accounts.sqlite3') as db:
            count=db.execute('SELECT COUNT(*) FROM support_messages').fetchone()[0]
            admin_count=db.execute('SELECT COUNT(*) FROM users WHERE is_admin=1').fetchone()[0]
            email=db.execute('SELECT email FROM users WHERE is_admin=1').fetchone()[0]
        check('initial admin exactly once',admin_count==1 and email=='nexus-owner@example.org')
        check('stored messages',count>=3)
        # Session + CSRF checks; no client supplied user/admin role trusted.
        check('invalid csrf rejected',req(user,f'/inquiries/{ticket}/send',{'csrf':'invalid','body':'x'})[0]==403)
        check('unknown route 404',req(anonymous,'/totally-unknown-route')[0]==404)
        # Logs and secrets are never served publicly.
        index=req(anonymous,'/')[1]
        check('secret not served',passwd not in index and 'pbkdf2_sha256$' not in index)
        proc.terminate();proc.wait(timeout=10)
        proc=subprocess.Popen([sys.executable,'app.py'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                if req(anonymous,'/healthz')[0]==200:break
            except OSError:time.sleep(.1)
        else:raise RuntimeError('restart failed')
        check('data persisted after restart',login(client(),'nexus_admin',passwd)[0]==200)
        with sqlite3.connect(Path(data)/'accounts.sqlite3') as db:
            check('ticket persisted after restart',db.execute('SELECT COUNT(*) FROM support_tickets').fetchone()[0]==1)
        print(f'PASS: {len(checks)} checks across login, 5 admin pages, messages, permissions, routes, security and persistence.')
    finally:
        proc.terminate()
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill()
