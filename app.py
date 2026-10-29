#!/usr/bin/env python3
"""Discord security bot site: SQLite accounts, PBKDF2 passwords, server-side sessions."""
from __future__ import annotations

import hashlib
import hmac
import html
import getpass
import sys
import os
import json
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent
INITIAL_ADMIN_SEED_FILE = ROOT / 'admin_seed.json'
TEMPLATES = ROOT / 'templates'
# Keep account and support records on durable storage, not in public site files.
DATA = Path(os.environ.get('DATA_DIR', str(ROOT / 'data'))).expanduser().resolve()
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'accounts.sqlite3'
SECRET_PATH = DATA / '.server_secret'
PRODUCTION = os.environ.get('APP_ENV', 'development').lower() == 'production'
COOKIE_SECURE = PRODUCTION or os.environ.get('COOKIE_SECURE') == '1'
MAX_POST = 65536
ITERATIONS = 310_000
SESSION_LIFETIME = 7 * 24 * 60 * 60
TYPING_TTL = 6
BOT_GREETING_DELAY = 3
RATE_LOCK = threading.Lock()
RATE_COUNTERS: dict[tuple[str,str],list[float]] = {}


def get_secret() -> bytes:
    key = os.environ.get('APP_SECRET')
    if key:
        if len(key) < 32:
            raise RuntimeError('APP_SECRET must be at least 32 characters')
        return key.encode()
    if not SECRET_PATH.exists():
        try:
            fd=os.open(SECRET_PATH, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'w') as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    return SECRET_PATH.read_text().strip().encode()

if PRODUCTION and not os.environ.get('APP_SECRET'):
    raise RuntimeError('Production requires APP_SECRET (32+ characters) as a hosting secret.')
if PRODUCTION and not os.environ.get('DATA_DIR'):
    raise RuntimeError('Production requires DATA_DIR pointing to persistent storage.')
SECRET = get_secret()


def db_conn():
    con = sqlite3.connect(DB, timeout=5)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys = ON')
    return con


def init_db():
    with db_conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_code TEXT DEFAULT NULL CHECK(plan_code IS NULL OR plan_code = 'free'),
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
        CREATE TABLE IF NOT EXISTS site_content (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            category TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            greeting_due INTEGER DEFAULT NULL,
            admin_unread INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_tickets_owner ON support_tickets(user_id, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_tickets_admin ON support_tickets(status, updated_at DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_one_open_per_category
          ON support_tickets(user_id, category) WHERE status='open';
        CREATE TABLE IF NOT EXISTS support_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
            sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            sender_type TEXT NOT NULL CHECK(sender_type IN ('system','member','admin')),
            body TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_ticket ON support_messages(ticket_id, id);
        CREATE TABLE IF NOT EXISTS support_typing (
            ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            touched_at INTEGER NOT NULL,
            PRIMARY KEY (ticket_id, user_id)
        );
        CREATE INDEX IF NOT EXISTS idx_typing_ticket ON support_typing(ticket_id, touched_at);
        
        """)
        # Database migration: existing users must remain unselected, rather than auto-enrolled.
        fields={row[1] for row in con.execute('PRAGMA table_info(users)')}
        if 'plan_code' not in fields:
            con.execute("ALTER TABLE users ADD COLUMN plan_code TEXT DEFAULT NULL CHECK(plan_code IS NULL OR plan_code = 'free')")
        if 'is_admin' not in fields:
            con.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
        ticket_fields={row[1] for row in con.execute('PRAGMA table_info(support_tickets)')}
        if 'greeting_due' not in ticket_fields:
            con.execute('ALTER TABLE support_tickets ADD COLUMN greeting_due INTEGER DEFAULT NULL')
        if 'admin_unread' not in ticket_fields:
            con.execute('ALTER TABLE support_tickets ADD COLUMN admin_unread INTEGER NOT NULL DEFAULT 0')



# Default copy is displayed until the site owner changes it in /admin.
# Text is escaped on render: editors cannot inject HTML or JavaScript.
CONTENT_FIELDS = {
    'home_title_1': ('메인 제목 (첫 줄)', '디스코드 서버 보안', 90),
    'home_title_2': ('메인 제목 (강조)', '기능 안내', 90),
    'home_description': ('메인 설명', '테러 감지 · 자동 복구 지원 · 긴급 경비 모드 · 보안 안내 · 입퇴장 및 퇴장 사유 관리', 500),
    'intro_title_1': ('기능 제목 (첫 줄)', 'Nexus', 90),
    'intro_title_2': ('기능 제목 (강조)', '제공 기능', 90),
    'intro_description': ('기능 설명', '서버 보안과 운영을 위한 기능을 항목별로 확인하세요.', 800),
    'intro_features_heading': ('기능 섹션 제목', '보안 및 관리 기능', 90),
    'intro_features_description': ('기능 섹션 설명', '각 기능을 선택 없이 한눈에 확인할 수 있습니다.', 500),
    'feature_1_title': ('1번 기능 이름', '실시간 서버 테러 감지', 90),
    'feature_1_description': ('1번 기능 목록 (줄마다 한 기능)', '메시지 도배 감지 — 짧은 시간에 대량으로 전송되는 메시지 감지\n채널 보호 — 채널 대량 생성 및 삭제 감지\n역할 보호 — 역할 대량 생성 및 삭제 감지\n이모지 보호 — 이모지 대량 생성 및 삭제 감지\n관리자 보안 알림 — 위험 활동 감지 시 관리자에게 즉시 알림', 950),
    'feature_2_title': ('2번 기능 이름', '자동 서버 복구 시스템', 90),
    'feature_2_description': ('2번 기능 목록 (줄마다 한 기능)', '삭제된 채널 복구 시도\n삭제된 역할 복구 시도\n삭제된 이모지 복구 시도\n비정상적으로 대량 생성된 항목 정리\n서버별 독립적인 백업 데이터 관리', 950),
    'feature_3_title': ('3번 기능 이름', '긴급 경비 모드', 90),
    'feature_3_description': ('3번 기능 목록 (줄마다 한 기능)', '일반 멤버의 채팅 일시 제한\n기본 1시간 동안 서버 보호\n위험 상황 종료 후 채팅 권한 복원\n관리자의 수동 경비 해제 지원\n기존 비공개 채널 권한 유지', 950),
    'feature_4_title': ('4번 기능 이름', '서버 전체 보안 안내', 90),
    'feature_4_description': ('4번 기능 목록 (줄마다 한 기능)', '경비 모드 전환 안내\n채팅 제한 사유 안내\n경비 모드 해제 예정 시간 표시\n중복 알림 방지\n상황에 따른 경비 모드 연장 또는 조기 해제 가능성 안내', 950),
    'feature_5_title': ('5번 기능 이름', '스마트 입퇴장 관리', 90),
    'feature_5_description': ('5번 기능 목록 (줄마다 한 기능)', '멤버 입장 및 퇴장 로그\n사용자 프로필 및 서버 정보 표시\n초대자 정보 추적 지원\n입퇴장 임베드 디자인 설정\n서버별 로그 채널 관리', 950),
    'feature_6_title': ('6번 기능 이름', '퇴장 사유 관리 시스템', 90),
    'feature_6_description': ('6번 기능 목록 (줄마다 한 기능)', '퇴장 사유 요청 DM 패널\n제출된 사유 관리자 전달\n관리자 확인 버튼\n확인 완료 시 감사 DM 전송\n중복 처리 방지\n퇴장 사유 확인 기록 보관', 950),
}


def get_content():
    with db_conn() as con:
        stored={r['key']: r['value'] for r in con.execute('SELECT key,value FROM site_content')}
    return {k: stored.get(k, desc[1]) for k,desc in CONTENT_FIELDS.items()}



def valid_discord_invite(value: str) -> bool:
    """Only accept official Discord bot OAuth2 authorization URLs."""
    if not value or len(value)>2048 or any(c.isspace() or ord(c)<32 for c in value):
        return False
    try:
        u=urlsplit(value)
        if (u.scheme != 'https' or u.hostname not in ('discord.com', 'discordapp.com')
                or u.username is not None or u.password is not None or u.port not in (None,443)
                or u.fragment or u.path not in ('/oauth2/authorize','/api/oauth2/authorize')):
            return False
        query=parse_qs(u.query,keep_blank_values=True,strict_parsing=False,max_num_fields=30)
        client=query.get('client_id',[])
        scope=query.get('scope',[])
        return (len(client)==1 and re.fullmatch(r'[0-9]{17,22}',client[0]) is not None
                and len(scope)==1 and 'bot' in scope[0].split())
    except (ValueError,UnicodeError):
        return False


def get_bot_invite_url() -> str:
    with db_conn() as con:
        row=con.execute("SELECT value FROM site_settings WHERE key='bot_invite_url'").fetchone()
    value=row['value'] if row else ''
    return value if valid_discord_invite(value) else ''


SUPPORT_CATEGORIES = {
    'general': ('일반 문의', '서비스 이용 및 계정 관련 문의'),
    'security': ('보안 기능 문의', '보안 기능과 서버 설정 관련 문의'),
    'technical': ('기술 지원', '설치·연결·작동 관련 문의'),
    'sanction': ('채팅 제재 문의', '채팅 제한이나 제재에 대한 문의'),
}
SYSTEM_GREETING = ("상담 채팅 이용 안내\n"
    "안녕하세요. Nexus 고객지원입니다. 이 대화는 문의자와 관리자만 확인할 수 있습니다.\n"
    "채팅 제재 안내: 욕설, 비방, 도배, 광고, 개인정보 공유 등 상담을 방해하는 행위는 "
    "상담 채팅 이용 제한의 사유가 될 수 있습니다.\n"
    "문의 내용을 남겨주시면 관리자가 확인한 뒤 답변드립니다. "
    "비밀번호, 인증 코드 등 민감한 정보는 보내지 마세요.")


def support_categories_html(csrf: str) -> str:
    parts=[]
    for key,(name,description) in SUPPORT_CATEGORIES.items():
        parts.append(f'<form class="support-category-card card reveal" action="/inquiries/start" method="post">'
           f'<input type="hidden" name="csrf" value="{html.escape(csrf,quote=True)}">'
           f'<input type="hidden" name="category" value="{key}">'
           f'<span class="support-small">1:1 비공개 상담</span>'
           f'<h3>{html.escape(name)}</h3><p>{html.escape(description)}</p>'
           f'<button class="btn btn-primary" type="submit">상담 시작하기 →</button></form>')
    return ''.join(parts)


def format_when(ts):
    return time.strftime('%Y-%m-%d %H:%M',time.localtime(ts))


def ticket_rows_html(rows, admin:bool) -> str:
    if not rows: return '<p class="empty-list">상담 내역이 없습니다.</p>'
    out=[]
    for r in rows:
        label=SUPPORT_CATEGORIES.get(r['category'],('문의',''))[0]
        who=f'<strong>{html.escape(r["username"])} 님</strong><span class="support-small"> · </span>' if admin else ''
        state='상담 중' if r['status']=='open' else '상담 종료'
        out.append(f'<a class="ticket-item" href="/inquiries/{r["id"]}">'
                   f'<div>{who}<strong>{html.escape(label)}</strong><div class="support-small">최근 활동 {format_when(r["updated_at"])}</div></div>'
                   f'<span class="ticket-status">{state} →</span></a>')
    return ''.join(out)


def render_message(row, own_id) -> str:
    kind=row['sender_type']
    # Keep positions consistent for both participants: admin left, customer right.
    person='안내 봇' if kind=='system' else ('관리자' if kind=='admin' else '문의자')
    cls=kind if kind in ('admin', 'member', 'system') else 'system'
    text=html.escape(row['body']).replace('\n','<br>')
    return (f'<article class="chat-bubble {cls}" data-message-id="{row["id"]}">'
            f'<div class="chat-meta">{person} · {format_when(row["created_at"])}</div>'
            f'<div class="chat-text">{text}</div></article>')


def feature_cards_html(content: dict[str,str]) -> str:
    """Build six safe, editable list cards from admin-managed text."""
    icons=('shield-check','database','lock','bell','users','clipboard')
    notes = {
      2: '일부 항목은 디스코드 시스템 및 권한 제한으로 인해 완전히 복구되지 않을 수 있습니다.',
      4: '개인 DM 수신 설정에 따라 일부 멤버에게 안내가 전달되지 않을 수 있습니다.',
    }
    parts=[]
    for i in range(1,7):
        title=html.escape(content[f'feature_{i}_title'],quote=True)
        rows=[x.strip() for x in content[f'feature_{i}_description'].splitlines() if x.strip()]
        bullet_html=''.join(f'<li>{html.escape(row,quote=True)}</li>' for row in rows)
        note=f'<p class="feature-note">{html.escape(notes[i])}</p>' if i in notes else ''
        parts.append(f'<article class="card feature-list-card reveal" style="--delay:{(i-1)%3*75}ms">'
                     f'<div class="feature-numeric">{i:02d} / 06</div><h3>{title}</h3>'
                     f'<ul class="feature-bullets">{bullet_html}</ul>{note}</article>')
    return '\n'.join(parts)

def text_for_html(text: str) -> str:
    return html.escape(text, quote=True).replace('\n', '<br>')


def create_admin():
    """One-time, console-only initial admin creation (never through public signup)."""
    init_db()
    with db_conn() as con:
        if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
            print('관리자 계정이 이미 있습니다. 초기 관리자 생성은 한 번만 가능합니다.')
            return 1
    if not sys.stdin.isatty():
        print('보안을 위해 관리자 생성은 서버 PC의 대화형 터미널에서만 가능합니다.')
        return 1
    username=input('관리자 아이디 (영문/숫자/_ 3~20자): ').strip()
    email=input('관리자 이메일: ').strip().lower()
    if not re.fullmatch(r'[A-Za-z0-9_]{3,20}', username):
        print('아이디 형식이 올바르지 않습니다.'); return 1
    if len(email)>254 or not re.fullmatch(r'[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,63}', email):
        print('이메일 형식이 올바르지 않습니다.'); return 1
    password=getpass.getpass('관리자 비밀번호 (12~128자): ')
    confirm=getpass.getpass('비밀번호 다시 입력: ')
    if len(password)<12 or len(password)>128 or password!=confirm:
        print('비밀번호는 12~128자로 설정하고 확인값과 일치해야 합니다.'); return 1
    digest=hash_password(password)
    try:
        with db_conn() as con:
            # Recheck inside write transaction to avoid creating multiple admins concurrently.
            con.execute('BEGIN IMMEDIATE')
            if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
                print('이미 관리자 계정이 있습니다.'); return 1
            con.execute('INSERT INTO users(username,email,password_hash,created_at,is_admin) VALUES(?,?,?,?,1)',
                        (username,email,digest,int(time.time())))
    except sqlite3.IntegrityError:
        print('이미 사용 중인 아이디 또는 이메일입니다. 다른 아이디로 다시 실행해 주세요.')
        return 1
    print('관리자 계정 생성 완료. 사이트 /login 에서 로그인한 뒤 /admin 에 접속하세요.')
    return 0

def change_admin_password():
    """Local administrator password change; never exposes password through a URL."""
    init_db()
    if not sys.stdin.isatty():
        print('관리자 비밀번호 변경은 서버 PC 터미널에서만 가능합니다.')
        return 1
    username=input('비밀번호를 변경할 관리자 아이디: ').strip()
    with db_conn() as con:
        row=con.execute('SELECT id,password_hash FROM users WHERE username=? COLLATE NOCASE AND is_admin=1', (username,)).fetchone()
    if row is None:
        print('관리자 계정을 찾을 수 없습니다.')
        return 1
    old=getpass.getpass('현재 비밀번호: ')
    if not check_password(old,row['password_hash']):
        print('현재 비밀번호가 올바르지 않습니다.')
        return 1
    new=getpass.getpass('새 비밀번호 (12~128자): ')
    again=getpass.getpass('새 비밀번호 확인: ')
    if new!=again or not 12 <= len(new) <= 128:
        print('새 비밀번호를 확인해 주세요.')
        return 1
    digest=hash_password(new)
    with db_conn() as con:
        con.execute('UPDATE users SET password_hash=? WHERE id=?',(digest,row['id']))
        con.execute('DELETE FROM sessions WHERE user_id=?',(row['id'],))
    print('관리자 비밀번호가 변경되었고, 기존 로그인 세션은 종료되었습니다.')
    return 0


def bootstrap_admin_from_env():
    """Secure one-time initial administrator creation for a cloud deployment.

    Prefer confidential hosting env vars; otherwise a packaged one-time hashed seed may be used.
    """
    username = os.environ.get('NEXUS_ADMIN_USERNAME', '').strip()
    email = os.environ.get('NEXUS_ADMIN_EMAIL', '').strip().lower()
    password = os.environ.get('NEXUS_ADMIN_PASSWORD', '')
    with db_conn() as con:
        if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
            return False
        if not (username and email and password):
            if PRODUCTION:
                raise RuntimeError('Production initial admin missing: set private NEXUS_ADMIN_USERNAME, NEXUS_ADMIN_EMAIL, NEXUS_ADMIN_PASSWORD environment variables.')
            return False
        if not re.fullmatch(r'[A-Za-z0-9_]{3,20}', username):
            raise RuntimeError('NEXUS_ADMIN_USERNAME must be 3-20 letters, digits, underscores.')
        if len(email)>254 or not re.fullmatch(r'[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,63}', email):
            raise RuntimeError('NEXUS_ADMIN_EMAIL must be a valid email address.')
        if not 14<=len(password)<=128 or password.lower() in ('passwordpassword', 'changemechangeme'):
            raise RuntimeError('NEXUS_ADMIN_PASSWORD must be a strong unique password of 14-128 characters.')
        con.execute('BEGIN IMMEDIATE')
        if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
            return False
        con.execute('INSERT INTO users(username,email,password_hash,created_at,is_admin) VALUES(?,?,?,?,1)',
                    (username,email,hash_password(password),int(time.time())))
    print('Nexus: initial administrator created; credentials are not shown in logs.')
    return True


def bootstrap_admin_from_seed():
    """Seed the owner once from a salted password hash; never replace a real account.

    The seed holds no plaintext password, works both with local SQLite and a fresh
    persistent cloud data volume, and is ignored when an admin already exists.
    """
    # The legacy offline seed is never accepted for a public production deployment.
    # Production must bootstrap an administrator with private environment variables.
    if PRODUCTION or not INITIAL_ADMIN_SEED_FILE.is_file():
        return False
    with db_conn() as con:
        if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
            return False
    try:
        seed=json.loads(INITIAL_ADMIN_SEED_FILE.read_text(encoding='utf-8'))
        username=seed['username']
        email=seed['email']
        digest=seed['password_hash']
        valid = (isinstance(username,str) and re.fullmatch(r'[A-Za-z0-9_]{3,20}',username)
                 and isinstance(email,str) and len(email)<=254
                 and re.fullmatch(r'[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,63}',email)
                 and isinstance(digest,str)
                 and re.fullmatch(r'pbkdf2_sha256\$310000\$[a-f0-9]{32}\$[a-f0-9]{64}',digest))
        if not valid:
            raise ValueError('invalid seed fields')
    except (OSError,KeyError,ValueError,TypeError,json.JSONDecodeError) as exc:
        raise RuntimeError('Nexus packaged initial admin seed is invalid') from exc
    with db_conn() as con:
        con.execute('BEGIN IMMEDIATE')
        if con.execute('SELECT 1 FROM users WHERE is_admin=1 LIMIT 1').fetchone():
            return False
        con.execute('INSERT INTO users(username,email,password_hash,created_at,is_admin) VALUES(?,?,?,?,1)',
                    (username,email,digest,int(time.time())))
    print('Nexus: packaged administrator initialized; change the password before sharing the site.')
    return True


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}'


def check_password(password: str, stored: str) -> bool:
    try:
        alg, n, salt, known = stored.split('$')
        if alg != 'pbkdf2_sha256' or int(n)>1_000_000 or int(n)<100_000:
            return False
        got=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(n))
        return hmac.compare_digest(got,bytes.fromhex(known))
    except (ValueError, OverflowError):
        return False


def sign_guest_csrf():
    value = secrets.token_hex(24)
    sig = hmac.new(SECRET, ('csrf:'+value).encode(), hashlib.sha256).hexdigest()
    return value+'.'+sig


def valid_guest_csrf(s):
    try:
        nonce, mac = s.split('.')
        if len(nonce)!=48 or not re.fullmatch(r'[a-f0-9]{48}',nonce): return False
        expected=hmac.new(SECRET,('csrf:'+nonce).encode(),hashlib.sha256).hexdigest()
        return hmac.compare_digest(mac,expected)
    except (ValueError,AttributeError):
        return False


def limited(ip: str, action: str, limit=12, window=900) -> bool:
    now=time.time()
    with RATE_LOCK:
        if len(RATE_COUNTERS)>10000:
            RATE_COUNTERS.clear()
        key=(ip,action)
        arr=[t for t in RATE_COUNTERS.get(key,[]) if now-t<window]
        RATE_COUNTERS[key]=arr
        if len(arr)>=limit:return True
        arr.append(now)
        return False


def ensure_bot_greeting(con, ticket_id: int, force=False):
    """Atomically deliver the scheduled initial bot notice once, before any member messages."""
    row=con.execute('SELECT greeting_due FROM support_tickets WHERE id=?',(ticket_id,)).fetchone()
    if row is None or row['greeting_due'] is None:
        return
    now=int(time.time())
    if not force and now < row['greeting_due']:
        return
    con.execute('UPDATE support_tickets SET greeting_due=NULL WHERE id=? AND greeting_due IS NOT NULL',(ticket_id,))
    if con.execute('SELECT changes()').fetchone()[0]:
        con.execute("INSERT INTO support_messages(ticket_id,sender_id,sender_type,body,created_at) VALUES(?,NULL,'system',?,?)",(ticket_id,SYSTEM_GREETING,now))


class Handler(BaseHTTPRequestHandler):
    server_version='Nexus'
    sys_version=''

    def cookies(self):
        parsed=SimpleCookie()
        try: parsed.load(self.headers.get('Cookie',''))
        except Exception: pass
        return {key:morsel.value for key,morsel in parsed.items()}

    def current(self):
        token=self.cookies().get('session','')
        if not re.fullmatch(r'[a-f0-9]{64}',token):return None
        digest=hashlib.sha256(token.encode()).hexdigest()
        with db_conn() as con:
            row=con.execute("""SELECT users.id, users.username, users.email, users.created_at, users.plan_code, users.is_admin,
                           sessions.csrf, sessions.expires_at, sessions.token_hash
                           FROM sessions JOIN users ON users.id=sessions.user_id
                           WHERE sessions.token_hash=? AND sessions.expires_at>?""",(digest,int(time.time()))).fetchone()
        return row

    def cookie_header(self,name,value,age=None,clear=False):
        parts=[f'{name}={value}','Path=/','HttpOnly','SameSite=Lax']
        if COOKIE_SECURE: parts.append('Secure')
        if age is not None: parts.append('Max-Age='+str(0 if clear else age))
        return '; '.join(parts)

    def headers_common(self,content_type,code=200,cookies=None):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Security-Policy',"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; worker-src 'none'")
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=()')
        self.send_header('Cross-Origin-Opener-Policy','same-origin')
        self.send_header('Cross-Origin-Resource-Policy','same-origin')
        if self.path.startswith(('/admin','/account','/api','/inquiries','/login','/signup')):
            self.send_header('X-Robots-Tag','noindex, nofollow, noarchive')
        if COOKIE_SECURE:self.send_header('Strict-Transport-Security','max-age=31536000')
        for c in cookies or []:self.send_header('Set-Cookie',c)

    def respond(self,body,code=200,cookies=None):
        content=body.encode('utf-8')
        self.headers_common('text/html; charset=utf-8',code,cookies)
        self.send_header('Content-Length',str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def respond_json(self, data, code=200):
        body=json.dumps(data,ensure_ascii=False).encode('utf-8')
        self.headers_common('application/json; charset=utf-8', code)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def ticket_details(self, ticket_id, user):
        with db_conn() as con:
            ticket=con.execute('''SELECT t.*,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id
                WHERE t.id=?''',(ticket_id,)).fetchone()
            if ticket and (user['is_admin'] or ticket['user_id']==user['id']):
                if user['is_admin']:
                    con.execute('UPDATE support_tickets SET admin_unread=0 WHERE id=?',(ticket_id,))
                ensure_bot_greeting(con,ticket_id)
                ticket=con.execute('''SELECT t.*,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id WHERE t.id=?''',(ticket_id,)).fetchone()
                messages=con.execute('SELECT * FROM support_messages WHERE ticket_id=? ORDER BY id ASC', (ticket_id,)).fetchall()
            else:messages=[]
        if not ticket or not (user['is_admin'] or ticket['user_id']==user['id']):
            return None,None
        return ticket,messages

    def render_support(self, name, user, ticket=None, messages=None):
        template=(TEMPLATES/'support.html').read_text(encoding='utf-8')
        csrf=html.escape(user['csrf'],quote=True)
        if name=='conversation':
            label=SUPPORT_CATEGORIES.get(ticket['category'],('문의',''))[0]
            state='상담 중' if ticket['status']=='open' else '상담 종료'
            chat_html=''.join(render_message(m,user['id']) for m in messages)
            form=(f'<form class="composer" method="post" action="/inquiries/{ticket["id"]}/send">'
                  f'<input type="hidden" name="csrf" value="{csrf}">'
                  '<label class="sr-only" for="chat-input">상담 메시지</label>'
                  '<textarea id="chat-input" name="body" maxlength="1500" rows="3" '
                  'placeholder="메시지를 입력하세요 (최대 1500자)" required></textarea>'
                  '<button type="submit" class="btn btn-primary">전송</button></form>') if ticket['status']=='open' else '<p class="chat-closed">종료된 상담입니다. 문의 페이지에서 새 상담을 시작할 수 있어요.</p>'
            close_form=''
            if user['is_admin']:
                next_status='closed' if ticket['status']=='open' else 'open'
                action='상담 종료' if next_status=='closed' else '상담 다시 열기'
                close_form=(f'<form method="post" action="/admin/inquiries/{ticket["id"]}/status">'
                            f'<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="status" value="{next_status}">'
                            f'<button class="btn" type="submit">{action}</button></form>')
            back='/admin/support' if user['is_admin'] else '/inquiries'
            content=(f'<div class="support-top"><a class="btn" href="{back}">← 상담 목록</a>{close_form}</div>'
                     f'<div class="support-panel"><div class="support-panel-head"><h2>{html.escape(label)}</h2>'
                     f'<p>{html.escape(ticket["username"])} 님 · {state} · 관리자와 비공개 대화</p></div>'
                     f'<div id="chat-log" class="chat-log" data-ticket-id="{ticket["id"]}">{chat_html}</div>'
                     f'<div class="typing-indicator" id="chat-typing" role="status" aria-live="polite" hidden>'
                     f'<span class="typing-dots" aria-hidden="true"><i></i><i></i><i></i></span>'
                     f'<span id="typing-label"></span></div>{form}</div>')
            script='''<script>
                (()=>{
                  const log=document.getElementById('chat-log');if(!log)return;
                  const id=log.dataset.ticketId;
                  const input=document.getElementById('chat-input');
                  const form=document.querySelector('form.composer');
                  const indicator=document.getElementById('chat-typing');
                  const label=document.getElementById('typing-label');
                  const csrf=form?.querySelector('input[name="csrf"]')?.value||'';
                  let last=Number(log.lastElementChild?.dataset.messageId||0);
                  let lastInput=0,lastHeartbeat=0,active=false,updating=false;
                  log.scrollTop=log.scrollHeight;
                  function setStatus(value){indicator.hidden=!value;if(value)label.textContent=value+' 작성 중…';}
                  async function heartbeat(isTyping){
                    if(!csrf||!form)return;
                    const now=Date.now();
                    if(isTyping&&active&&now-lastHeartbeat<1700)return;
                    active=isTyping;lastHeartbeat=now;
                    try{await fetch('/api/inquiries/'+id+'/typing',{
                      method:'POST',credentials:'same-origin',cache:'no-store',
                      headers:{'Content-Type':'application/x-www-form-urlencoded'},
                      body:new URLSearchParams({csrf,active:isTyping?'1':'0'})
                    });}catch(e){}
                  }
                  input?.addEventListener('input',()=>{
                    lastInput=Date.now();
                    if(input.value.trim())heartbeat(true);else heartbeat(false);
                  });
                  input?.addEventListener('blur',()=>{if(active)heartbeat(false);});
                  form?.addEventListener('submit',()=>{heartbeat(false);});
                  async function update(){
                    if(document.hidden||updating)return;
                    updating=true;
                    try{
                      const r=await fetch('/api/inquiries/'+id+'/messages?after='+last,{credentials:'same-origin',cache:'no-store'});
                      if(!r.ok)return;
                      const j=await r.json();
                      for(const m of j.messages){if(m.id<=last)continue;
                        const el=document.createElement('article');el.className='chat-bubble '+(m.type==='admin'?'admin':m.type==='member'?'member':'system');
                        el.dataset.messageId=m.id;
                        const meta=document.createElement('div');meta.className='chat-meta';
                        meta.textContent=(m.type==='system'?'안내 봇':m.type==='admin'?'관리자':'문의자')+' · '+m.when;
                        const msg=document.createElement('div');msg.className='chat-text';msg.textContent=m.body;
                        el.append(meta,msg);log.append(el);last=m.id;log.scrollTop=log.scrollHeight;
                      }
                      setStatus(j.typing||'');
                      if(j.status==='closed'&&!document.querySelector('.chat-closed'))location.reload();
                      if(j.status==='closed'){setStatus('');if(active)heartbeat(false);}
                    }catch(e){}finally{updating=false;}
                  }
                  setInterval(()=>{
                    if(active&&(!input?.value.trim()||Date.now()-lastInput>3500))heartbeat(false);
                    else if(active)heartbeat(true);
                    update();
                  },1300);
                  update();
                })();</script>'''
        else:
            admin=name=='admin_list'
            with db_conn() as con:
                if admin:
                    rows=con.execute('''SELECT t.*,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id
                                       ORDER BY (t.status='open') DESC, t.updated_at DESC LIMIT 150''').fetchall()
                else:
                    rows=con.execute('''SELECT t.*,u.username FROM support_tickets t JOIN users u ON u.id=t.user_id
                                       WHERE t.user_id=? ORDER BY (t.status='open') DESC, t.updated_at DESC LIMIT 100''',(user['id'],)).fetchall()
            content=('<div class="actions" style="justify-content:flex-start;margin:8px 0 18px"><a class="btn" href="/admin/dashboard">← 관리자 패널</a></div>' if admin else '')
            content+='<div class="support-panel"><h2>'+('관리자 상담 목록' if admin else '나의 상담 내역')+'</h2>'
            content+=('<p class="support-muted">회원별 비공개 문의와 답변을 관리합니다.</p>' if admin
                      else '<p class="support-muted">내 상담 내역은 본인과 관리자만 확인할 수 있습니다.</p>')
            content+=ticket_rows_html(rows,admin)+'</div>'
            content+='<div class="actions"><a class="btn" href="/contact.html">문의 유형 선택하기</a></div>'
            script=''
        auth=f'<a class="auth-button" href="/account">{html.escape(user["username"])} 님</a>'
        if user['is_admin']:auth='<a class="auth-button" href="/admin/support">상담 관리</a><a class="auth-button" href="/admin/dashboard">관리자</a>'+auth
        auth+=f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="auth-button primary" type="submit">로그아웃</button></form>'
        title='비공개 상담' if name=='conversation' else ('관리자 상담 관리' if name=='admin_list' else '나의 상담')
        for x,y in {'{{AUTH_ACTIONS}}':auth,'{{SUPPORT_TITLE}}':title,'{{SUPPORT_BODY}}':content,'{{SUPPORT_SCRIPT}}':script}.items(): template=template.replace(x,y)
        self.respond(template)

    def redirect(self,where,cookies=None):
        self.headers_common('text/plain; charset=utf-8',303,cookies)
        self.send_header('Location',where)
        self.send_header('Content-Length','0')
        self.end_headers()

    def admin_data(self):
        """Counts and recent account summaries; only invoke after admin access check."""
        with db_conn() as con:
            stats={
                'members':con.execute('SELECT COUNT(*) FROM users WHERE is_admin=0').fetchone()[0],
                'free':con.execute("SELECT COUNT(*) FROM users WHERE is_admin=0 AND plan_code='free'").fetchone()[0],
                'open':con.execute("SELECT COUNT(*) FROM support_tickets WHERE status='open'").fetchone()[0],
                'tickets':con.execute('SELECT COUNT(*) FROM support_tickets').fetchone()[0],
            }
            members=con.execute("SELECT username,plan_code,created_at FROM users WHERE is_admin=0 ORDER BY created_at DESC,id DESC LIMIT 100").fetchall()
        labels=[('가입 회원',stats['members']),('무료 플랜 선택',stats['free']),('진행 중 상담',stats['open']),('전체 상담',stats['tickets'])]
        cards=''.join(f'<div class="admin-stat"><p>{label}</p><strong>{value:,}</strong></div>' for label,value in labels)
        rows=''.join('<tr><td>'+html.escape(m['username'])+'</td>'
            +'<td><span class="admin-plan-pill '+('active' if m['plan_code']=='free' else '')+'">'
            +('FREE · 무료' if m['plan_code']=='free' else '선택한 플랜 없음')+'</span></td>'
            +'<td>'+time.strftime('%Y-%m-%d',time.localtime(m['created_at']))+'</td></tr>' for m in members)
        with db_conn() as con:
            tickets=con.execute('''SELECT t.*,u.username,
                    (SELECT m.body FROM support_messages m WHERE m.ticket_id=t.id AND m.sender_type!='system'
                     ORDER BY m.id DESC LIMIT 1) AS latest_body
                    FROM support_tickets t JOIN users u ON u.id=t.user_id
                    ORDER BY (t.status='open') DESC,t.updated_at DESC LIMIT 150''').fetchall()
        tickets_html=''
        for t in tickets:
            title=SUPPORT_CATEGORIES.get(t['category'],('일반 문의',''))[0]
            line=html.escape((t['latest_body'] or '새 상담이 생성되었습니다.')[:110])
            tickets_html+=(f'<a class="ticket-item" href="/inquiries/{t["id"]}">'
              f'<div><strong>{html.escape(t["username"])} 님 · {html.escape(title)}</strong>'
              f'<div class="support-small">{line}</div>'
              f'<div class="support-small">최근 활동 {format_when(t["updated_at"])}</div></div>'
              f'<span class="ticket-status">{("상담 중" if t["status"]=="open" else "상담 종료")} →</span></a>')
        return cards,rows or '<tr><td colspan="3">가입한 회원이 없습니다.</td></tr>',tickets_html or '<p class="empty-list">아직 접수된 문의가 없습니다.</p>'

    def page(self,name,user=None,error='',values=None,csrf='',status=200,cookies=None):
        values=values or {}
        page=(TEMPLATES/f'{name}.html').read_text(encoding='utf-8')
        if user:
            auth=(f'<a class="auth-button" href="/account">{html.escape(user["username"])} 님</a>'
                  f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{html.escape(user["csrf"])}">'
                  f'<button type="submit" class="auth-button primary">로그아웃</button></form>')
            if user['is_admin']:
                auth='<a class="auth-button" href="/admin/support">상담 관리</a><a class="auth-button" href="/admin/dashboard">관리자</a>'+auth
        else:
            auth='<a class="auth-button" href="/signup">가입</a><a class="auth-button primary" href="/login">로그인</a>'
        plan = user['plan_code'] if user else None
        invite_url=get_bot_invite_url()
        if user and plan == 'free':
            plan_action=('<span class="status-chip" role="status">현재 플랜</span>'
                         '<a class="btn btn-primary" href="/invite-bot">봇 초대하기 ↗</a>')
            plan_label='<span class="status-chip">현재 플랜 · FREE 무료</span>'
            plan_cta='<a class="btn btn-primary" href="/invite-bot">봇 초대하기 ↗</a>'
        elif user:
            plan_action=(
                '<form method="post" action="/select-plan">'
                f'<input type="hidden" name="csrf" value="{html.escape(user["csrf"])}">'
                '<input type="hidden" name="plan_code" value="free">'
                '<button type="submit" class="btn btn-primary">무료 플랜 선택하고 봇 초대하기 ↗</button>'
                '</form>'
            )
            plan_label='<span class="plan-unselected">선택한 플랜이 없습니다</span>'
            plan_cta='<a class="btn btn-primary" href="/plans.html">플랜 선택하러 가기 ↗</a>'
        else:
            plan_action='<a class="btn btn-primary" href="/login">로그인하고 무료 플랜 선택하기 ↗</a>'
            plan_label='<span class="plan-unselected">선택한 플랜이 없습니다</span>'
            plan_cta=''
        content=get_content() if name in ('index','intro','admin') else {}
        query=parse_qs(urlsplit(self.path).query)
        active_tab=(values or {}).get('admin_tab',query.get('tab',['dashboard'])[0])
        if active_tab not in ('dashboard','content','plans','members','inquiries'): active_tab='dashboard'
        if name=='admin' and user and user['is_admin']:
            admin_stats,admin_members,admin_tickets=self.admin_data()
            with db_conn() as con:
                admin_unread=con.execute('SELECT COUNT(*) FROM support_tickets WHERE admin_unread=1').fetchone()[0]
        else:
            admin_stats,admin_members,admin_tickets='','',''
            admin_unread=0

        replacements={
            '{{ADMIN_TAB}}':active_tab,
            '{{ADMIN_STATS}}':admin_stats,
            '{{ADMIN_MEMBER_ROWS}}':admin_members,
            '{{ADMIN_TICKETS}}':admin_tickets,
            '{{ADMIN_UNREAD}}':str(admin_unread) if admin_unread<=99 else '99+',
            '{{ADMIN_UNREAD_HIDDEN}}':'' if admin_unread else 'hidden',
            "{{ADMIN_ACTIVE:inquiries}}":'aria-current="page"' if active_tab=="inquiries" else "",
            "{{ADMIN_ACTIVE:dashboard}}":'aria-current="page"' if active_tab=="dashboard" else "",
            "{{ADMIN_ACTIVE:content}}":'aria-current="page"' if active_tab=="content" else "",
            "{{ADMIN_ACTIVE:plans}}":'aria-current="page"' if active_tab=="plans" else "",
            "{{ADMIN_ACTIVE:members}}":'aria-current="page"' if active_tab=="members" else "",
            '{{ADMIN_LINK}}': ('<a class="btn btn-primary" href="/admin/dashboard">관리자 · 기능 관리</a>' if user and user['is_admin'] else ''),
            '{{SAVE_MESSAGE}}': ('<div class="saved-alert" role="status">기능 내용이 저장되었습니다. 공개 페이지에 바로 반영됩니다.</div>' if name=='admin' and '1' in query.get('saved',[]) else ''),
            '{{PASSWORD_NOTICE}}': ('<div class="saved-alert" role="status">관리자 비밀번호가 변경되었습니다. 새 비밀번호로 로그인해 주세요.</div>' if name=='login' and '1' in query.get('password_changed',[]) else ''),
            '{{ADMIN_PASSWORD_ERROR}}': ('<div class="auth-alert" role="alert">'+html.escape(error)+'</div>' if name=='admin' and active_tab=='dashboard' and error else ''),
            '{{INVITE_URL}}':html.escape(invite_url,quote=True),
            '{{INVITE_STATUS}}':('봇 초대 링크가 설정되어 있습니다.' if invite_url else '봇 초대 링크를 입력하고 저장하면 플랜에서 연결됩니다.'),
            '{{INVITE_SAVE_MESSAGE}}':('<div class="saved-alert" role="status">봇 초대 링크를 저장했습니다.</div>' if name=='admin' and '1' in query.get('invite_saved',[]) else ''),
            '{{INVITE_ERROR}}':('<div class="auth-alert" role="alert">'+html.escape(error)+'</div>' if name=='admin' and error else ''),
            '{{PLAN_ACTION}}':plan_action,
            '{{PLAN_NAME}}':plan_label,
            '{{PLAN_CTA}}':plan_cta,
            '{{PLAN_NOTE}}':('무료 플랜을 이용하고 있습니다. 봇 초대하기 버튼을 눌러 서버에 추가할 수 있습니다.' if plan == 'free' else '선택한 플랜이 없습니다. 플랜 페이지에서 선택해 주세요.'),
            '{{AUTH_ACTIONS}}':auth,
            '{{ERROR}}':('<div class="auth-alert" role="alert">'+html.escape(error)+'</div>') if error else '',
            '{{CSRF}}':html.escape(csrf or (user['csrf'] if user else '')),
            '{{USERNAME}}':html.escape(user['username'] if user else values.get('username','')),
            '{{EMAIL}}':html.escape(user['email'] if user else values.get('email','')),
            '{{JOINED}}':time.strftime('%Y-%m-%d',time.localtime(user['created_at'])) if user else '',
            '{{IDENTIFIER}}':html.escape(values.get('identifier','')),
        }
        if name == 'contact':
            replacements['{{SUPPORT_CATEGORIES}}']=support_categories_html(user['csrf'] if user else '')
            replacements['{{SUPPORT_HISTORY}}']=('<a class="btn" href="/inquiries">내 상담 내역 보기 →</a>' if user else '<a class="btn" href="/login">로그인하고 문의하기 →</a>')
        if name == 'intro':
            replacements['{{FEATURE_CARDS}}'] = feature_cards_html(content)
        for k, v in content.items():
            replacements['{{CONTENT:'+k+'}}']=text_for_html(v)
            replacements['{{VALUE:'+k+'}}']=html.escape(v,quote=True)
        for k,v in replacements.items(): page=page.replace(k,v)
        self.respond(page,status,cookies)

    def do_GET(self):
        url=urlsplit(self.path)
        path=url.path
        if path == '/healthz':
            # Deployment health checks must verify storage, not merely the HTTP process.
            # Never expose database paths, errors or credentials in this public endpoint.
            try:
                with db_conn() as con:
                    con.execute('SELECT 1').fetchone()
            except (sqlite3.Error, OSError):
                self.respond_json({'status':'unavailable'},503)
                return
            self.respond_json({'status':'ok'})
            return
        if path == '/robots.txt':
            b=b'User-agent: *\nDisallow: /admin\nDisallow: /account\nDisallow: /inquiries\nDisallow: /api\nDisallow: /signup\nDisallow: /login\n'
            self.headers_common('text/plain; charset=utf-8')
            self.send_header('Content-Length',str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if path == '/favicon.png':
            b=(ROOT/'nz_nexus_logo.png').read_bytes()
            self.headers_common('image/png')
            self.send_header('Content-Length',str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if path == '/api/admin/inquiries/unread':
            user=self.current()
            if not user:
                self.respond_json({'error':'login required'},401);return
            if not user['is_admin']:
                self.respond_json({'error':'forbidden'},403);return
            with db_conn() as con:
                unread=con.execute('SELECT COUNT(*) FROM support_tickets WHERE admin_unread=1').fetchone()[0]
            self.respond_json({'unread':unread});return
        if path == '/api/admin/inquiries':
            user=self.current()
            if not user:
                self.respond_json({'error':'login required'},401);return
            if not user['is_admin']:
                self.respond_json({'error':'forbidden'},403);return
            with db_conn() as con:
                tickets=con.execute("""SELECT t.id,t.category,t.status,t.updated_at,t.admin_unread,u.username,
                      (SELECT m.body FROM support_messages m WHERE m.ticket_id=t.id AND m.sender_type!='system'
                       ORDER BY m.id DESC LIMIT 1) AS latest_body
                      FROM support_tickets t JOIN users u ON u.id=t.user_id
                      ORDER BY (t.status='open') DESC,t.updated_at DESC LIMIT 150""").fetchall()
                open_count=con.execute("SELECT COUNT(*) FROM support_tickets WHERE status='open'").fetchone()[0]
                total=con.execute("SELECT COUNT(*) FROM support_tickets").fetchone()[0]
                unread=con.execute("SELECT COUNT(*) FROM support_tickets WHERE admin_unread=1").fetchone()[0]
            self.respond_json({'open':open_count,'total':total,'unread':unread,
                'tickets':[{'id':t['id'],'username':t['username'],
                    'category':SUPPORT_CATEGORIES.get(t['category'],('문의',''))[0],
                    'status':t['status'],'when':format_when(t['updated_at']),
                    'latest':(t['latest_body'] or '새 상담이 생성되었습니다.')[:110],
                    'unread':bool(t['admin_unread'])} for t in tickets]})
            return
        if path == '/admin/inquiries':
            self.redirect('/admin/support');return
        if path == '/inquiries':
            user=self.current()
            if not user: self.redirect('/login');return
            if path=='/admin/inquiries' and not user['is_admin']:
                self.respond('<h1>403</h1>',403);return
            self.render_support('member_list',user)
            return
        m=re.fullmatch(r'/inquiries/(\d+)',path)
        api=re.fullmatch(r'/api/inquiries/(\d+)/messages',path)
        if m or api:
            user=self.current()
            if not user:
                if api:self.respond_json({'error':'login required'},401)
                else:self.redirect('/login')
                return
            ticket,messages=self.ticket_details(int((m or api).group(1)),user)
            if ticket is None:
                if api:self.respond_json({'error':'not found'},404)
                else:self.respond('<h1>404</h1>',404)
                return
            if api:
                try:
                    after=int(parse_qs(url.query).get('after',['0'])[0]);after=max(0,min(after,2**63-1))
                except (ValueError,OverflowError):after=0
                selected=[msg for msg in messages if msg['id']>after][:100]
                typing=''
                if ticket['status']=='open':
                    with db_conn() as con:
                        other=con.execute('''SELECT u.username,u.is_admin FROM support_typing x
                          JOIN users u ON u.id=x.user_id
                          WHERE x.ticket_id=? AND x.user_id<>? AND x.touched_at>?
                          ORDER BY x.touched_at DESC LIMIT 1''',
                          (ticket['id'],user['id'],int(time.time())-TYPING_TTL)).fetchone()
                    if other:
                        typing='관리자가' if other['is_admin'] else other['username']+'님이'
                    elif ticket['greeting_due'] is not None and int(time.time()) < ticket['greeting_due']:
                        typing='안내 봇이'
                self.respond_json({'status':ticket['status'],'typing':typing, 'messages':[
                    {'id':msg['id'],'type':msg['sender_type'],'own':msg['sender_id']==user['id'] and msg['sender_type']!='system',
                     'body':msg['body'],'when':format_when(msg['created_at'])} for msg in selected]})
            else:self.render_support('conversation',user,ticket,messages)
            return
        admin_routes = {
            '/admin/dashboard':'dashboard',
            '/admin/content':'content',
            '/admin/plans':'plans',
            '/admin/members':'members',
            '/admin/support':'inquiries',
        }
        if path == '/admin':
            section=parse_qs(url.query).get('tab',['dashboard'])[0]
            legacy={'inquiries':'support'}.get(section,section)
            if legacy not in ('dashboard','content','plans','members','support'):legacy='dashboard'
            self.redirect('/admin/'+legacy);return
        if path in admin_routes:
            admin=self.current()
            if not admin:
                self.redirect('/login');return
            if not admin['is_admin']:
                self.respond('<h1>403 접근 권한이 없습니다.</h1>',403);return
            self.page('admin',user=admin,values={'admin_tab':admin_routes[path]})
            return
        # Common friendly addresses should redirect to the canonical HTML routes.
        # Avoids a 404 from manually entered links; does not replace real server hosting.
        path_aliases = {
            '/home': '/',
            '/intro': '/intro.html',
            '/features': '/intro.html',
            '/plans': '/plans.html',
            '/creator': '/creator.html',
            '/contact': '/contact.html',
            '/support': '/contact.html',
        }
        if path in path_aliases:
            self.redirect(path_aliases[path]);return
        public={'/':'index','/index.html':'index','/intro.html':'intro','/plans.html':'plans','/creator.html':'creator','/contact.html':'contact',
                '/signup':'signup','/signup.html':'signup','/login':'login','/login.html':'login','/account':'account','/account.html':'account','/admin':'admin'}
        if path == '/invite-bot':
            user=self.current()
            if not user:
                self.redirect('/login');return
            if user['plan_code'] != 'free':
                self.redirect('/plans.html');return
            link=get_bot_invite_url()
            if not link:
                self.page('plans',user=user,error='봇 초대 링크가 설정되지 않았습니다. 관리자에게 문의하세요.',status=503)
                return
            self.redirect(link)
            return
        if path not in public:
            self.respond('<h1>404</h1>',404);return
        name=public[path]
        user=self.current()
        if name in ('account','admin') and not user:
            self.redirect('/login');return
        if name=='admin' and not user['is_admin']:
            self.respond('<h1>403 접근 권한이 없습니다.</h1>',403);return
        if name in ('signup','login') and user:
            self.redirect('/account');return
        if name in ('signup','login'):
            csrf=sign_guest_csrf()
            self.page(name,csrf=csrf,cookies=[self.cookie_header('guest_csrf',csrf,age=3600)])
        else:self.page(name,user=user)

    def get_form(self):
        try:
            length=int(self.headers.get('Content-Length','0'))
            if length<=0 or length>MAX_POST:return None
            raw=self.rfile.read(length).decode('utf-8')
            parsed=parse_qs(raw,keep_blank_values=True,max_num_fields=32)
            if any(len(v)!=1 for v in parsed.values()):return None
            return {k:v[0] for k,v in parsed.items()}
        except (ValueError,UnicodeError):return None

    def do_POST(self):
        path=urlsplit(self.path).path
        if path not in ('/signup','/login','/logout','/select-plan','/admin/save-intro','/admin/save-invite','/admin/change-password','/inquiries/start') and not re.fullmatch(r'/inquiries/\d+/send|/admin/inquiries/\d+/status|/api/inquiries/\d+/typing',path):
            self.respond('<h1>404</h1>',404);return
        if self.headers.get('Content-Type','').split(';')[0].strip()!='application/x-www-form-urlencoded':
            self.respond('Unsupported media type',415);return
        form=self.get_form()
        if form is None:self.respond('Invalid request',400);return
        user=self.current()
        typing_match=re.fullmatch(r'/api/inquiries/(\d+)/typing',path)
        if typing_match:
            if not user:self.respond_json({'error':'login required'},401);return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond_json({'error':'forbidden'},403);return
            if form.get('active') not in ('0','1'):
                self.respond_json({'error':'invalid state'},400);return
            ticket_id=int(typing_match.group(1))
            if limited(str(user['id']),f'typing:{ticket_id}',75,60):
                self.respond_json({'error':'too many updates'},429);return
            with db_conn() as con:
                ticket=con.execute('SELECT user_id,status FROM support_tickets WHERE id=?',(ticket_id,)).fetchone()
                if not ticket or (ticket['user_id']!=user['id'] and not user['is_admin']):
                    self.respond_json({'error':'not found'},404);return
                if ticket['status']!='open':
                    self.respond_json({'error':'closed'},409);return
                if form['active']=='1':
                    con.execute('''INSERT INTO support_typing(ticket_id,user_id,touched_at) VALUES(?,?,?)
                        ON CONFLICT(ticket_id,user_id) DO UPDATE SET touched_at=excluded.touched_at''',
                        (ticket_id,user['id'],int(time.time())))
                else:con.execute('DELETE FROM support_typing WHERE ticket_id=? AND user_id=?',(ticket_id,user['id']))
            self.respond_json({'ok':True});return
        if path=='/inquiries/start':
            if not user:self.redirect('/login');return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            category=form.get('category','')
            if category not in SUPPORT_CATEGORIES:self.respond('Invalid category',400);return
            if limited(str(user['id']),'ticket-create',12,3600):
                self.respond('요청이 너무 많습니다.',429);return
            now=int(time.time())
            with db_conn() as con:
                con.execute('BEGIN IMMEDIATE')
                row=con.execute("SELECT id FROM support_tickets WHERE user_id=? AND category=? AND status='open'",(user['id'],category)).fetchone()
                if row: ticket_id=row['id']
                else:
                    cur=con.execute('INSERT INTO support_tickets(user_id,category,status,created_at,updated_at,greeting_due) VALUES(?,?,?,?,?,?)',(user['id'],category,'open',now,now,now+BOT_GREETING_DELAY))
                    ticket_id=cur.lastrowid
            self.redirect(f'/inquiries/{ticket_id}');return
        m=re.fullmatch(r'/inquiries/(\d+)/send',path)
        if m:
            if not user:self.redirect('/login');return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):self.respond('Forbidden',403);return
            ticket_id=int(m.group(1))
            body=form.get('body','').strip()
            if not body or len(body)>1500 or '\x00' in body:
                self.respond('메시지는 1~1500자로 입력해 주세요.',400);return
            if limited(str(user['id']),'ticket-message',30,60):self.respond('Too many messages',429);return
            with db_conn() as con:
                con.execute('BEGIN IMMEDIATE')
                ticket=con.execute('SELECT * FROM support_tickets WHERE id=?',(ticket_id,)).fetchone()
                if not ticket or (ticket['user_id']!=user['id'] and not user['is_admin']):
                    self.respond('<h1>403</h1>',403);return
                if ticket['status']!='open':self.respond('상담이 종료되었습니다.',409);return
                ensure_bot_greeting(con,ticket_id,force=True)
                con.execute('DELETE FROM support_typing WHERE ticket_id=? AND user_id=?',(ticket_id,user['id']))
                kind='admin' if user['is_admin'] else 'member'
                now=int(time.time())
                con.execute('INSERT INTO support_messages(ticket_id,sender_id,sender_type,body,created_at) VALUES(?,?,?,?,?)',(ticket_id,user['id'],kind,body,now))
                con.execute('UPDATE support_tickets SET updated_at=?, admin_unread=? WHERE id=?',(now, 0 if user['is_admin'] else 1, ticket_id))
            self.redirect(f'/inquiries/{ticket_id}');return
        m=re.fullmatch(r'/admin/inquiries/(\d+)/status',path)
        if m:
            if not user:self.redirect('/login');return
            if not user['is_admin'] or not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('<h1>403</h1>',403);return
            status=form.get('status','')
            if status not in ('open','closed'):self.respond('Invalid status',400);return
            ticket_id=int(m.group(1))
            try:
                with db_conn() as con:
                    con.execute('UPDATE support_tickets SET status=?, updated_at=? WHERE id=?',(status,int(time.time()),ticket_id))
                    if status=='closed':
                        con.execute('UPDATE support_tickets SET admin_unread=0 WHERE id=?',(ticket_id,))
                        con.execute('DELETE FROM support_typing WHERE ticket_id=?',(ticket_id,))
            except sqlite3.IntegrityError:
                self.respond('이미 이 유형으로 열린 상담이 있습니다.',409);return
            self.redirect(f'/inquiries/{ticket_id}');return
        if path=='/admin/change-password':
            if not user:
                self.redirect('/login');return
            if not user['is_admin']:
                self.respond('<h1>403</h1>',403);return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            # Keep password checks and hashes on the server; never echo secrets.
            if limited(str(user['id']),'admin-password',7,3600):
                self.respond('Too many requests',429);return
            old=form.get('current_password','')
            new=form.get('new_password','')
            confirm=form.get('confirm_password','')
            if (not 14<=len(new)<=128 or new!=confirm or new==old):
                self.page('admin',user=user,error='새 비밀번호는 기존과 달라야 하며 14~128자로 일치하게 입력해야 합니다.',values={'admin_tab':'dashboard'},status=400)
                return
            with db_conn() as con:
                con.execute('BEGIN IMMEDIATE')
                record=con.execute('SELECT password_hash FROM users WHERE id=? AND is_admin=1',(user['id'],)).fetchone()
                if not record or not check_password(old,record['password_hash']):
                    self.page('admin',user=user,error='현재 비밀번호를 확인해 주세요.',values={'admin_tab':'dashboard'},status=400)
                    return
                con.execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(new),user['id']))
                con.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
            self.redirect('/login?password_changed=1',cookies=[self.cookie_header('session','',clear=True,age=0)])
            return
        if path=='/admin/save-invite':
            if not user:
                self.redirect('/login');return
            if not user['is_admin']:
                self.respond('<h1>403 접근 권한이 없습니다.</h1>',403);return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            if limited(self.client_address[0],'admin-invite',15,60):
                self.respond('Too many requests',429);return
            value=form.get('bot_invite_url','').strip()
            if not valid_discord_invite(value):
                self.page('admin',user=user,error='올바른 Discord 봇 초대 링크를 입력해 주세요. (https://discord.com/oauth2/authorize?...&scope=bot)',values={'admin_tab':'plans'},status=400)
                return
            with db_conn() as con:
                con.execute('''INSERT INTO site_settings(key,value,updated_at) VALUES('bot_invite_url',?,?)
                        ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at''',
                        (value,int(time.time())))
            self.redirect('/admin/plans?invite_saved=1');return
        if path=='/admin/save-intro':
            if not user:
                self.redirect('/login');return
            if not user['is_admin']:
                self.respond('<h1>403 접근 권한이 없습니다.</h1>',403);return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            if limited(self.client_address[0],'admin-save',30,60):
                self.respond('Too many requests',429);return
            edited={}
            for key,(label,default,max_chars) in CONTENT_FIELDS.items():
                val=form.get(key, '').strip()
                if not val or len(val)>max_chars or '\x00' in val:
                    self.page('admin',user=user,error=f'{label}: 1~{max_chars}자 이내로 입력해 주세요.',values={'admin_tab':'content'},status=400)
                    return
                edited[key]=val
            with db_conn() as con:
                now=int(time.time())
                con.executemany('''INSERT INTO site_content(key,value,updated_at) VALUES(?,?,?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at''',
                    [(key,val,now) for key,val in edited.items()])
            self.redirect('/admin/content?saved=1');return
        if path=='/select-plan':
            if not user:
                self.redirect('/login');return
            if not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            if form.get('plan_code') != 'free':
                self.respond('Invalid plan',400);return
            link=get_bot_invite_url()
            if not link:
                self.page('plans',user=user,error='봇 초대 링크가 설정되지 않았습니다. 관리자에게 문의하세요.',status=503)
                return
            with db_conn() as con:
                con.execute("UPDATE users SET plan_code='free' WHERE id=? AND plan_code IS NULL",(user['id'],))
            self.redirect(link);return
        if path=='/logout':
            if not user or not hmac.compare_digest(form.get('csrf',''),user['csrf']):
                self.respond('Forbidden',403);return
            with db_conn() as con:
                con.execute('DELETE FROM sessions WHERE token_hash=?',(user['token_hash'],))
            self.redirect('/',[self.cookie_header('session','',clear=True,age=0)]);return
        if user:
            self.redirect('/account');return
        csrf=form.get('csrf','')
        if not valid_guest_csrf(csrf) or not hmac.compare_digest(csrf,self.cookies().get('guest_csrf','')):
            self.respond('잘못된 요청입니다. 다시 페이지를 열어 주세요.',403);return
        # Do not use untrusted X-Forwarded-For: only the direct socket peer.
        ip=self.client_address[0]
        if limited(ip,path,12,900):
            self.page('signup' if path=='/signup' else 'login',error='요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.',csrf=csrf,status=429)
            return
        if path=='/signup':
            username=form.get('username','').strip()
            email=form.get('email','').strip().lower()
            password=form.get('password','')
            confirm=form.get('confirm_password','')
            values={'username':username,'email':email}
            error=''
            if not re.fullmatch('[A-Za-z0-9_]{3,20}',username):
                error='아이디는 영문, 숫자, 밑줄(_) 3~20자로 입력해 주세요.'
            elif len(email)>254 or not re.fullmatch(r'[^@\s<>]{1,64}@[^@\s<>]{1,190}\.[A-Za-z]{2,63}',email):
                error='이메일 주소를 확인해 주세요.'
            elif len(password)<10 or len(password)>128:
                error='비밀번호는 10~128자로 입력해 주세요.'
            elif password!=confirm:
                error='비밀번호 확인이 일치하지 않습니다.'
            if error:
                self.page('signup',error=error,values=values,csrf=csrf,status=400);return
            # PBKDF2 is intentionally performed before probing for duplicate accounts.
            digest=hash_password(password)
            try:
                with db_conn() as con:
                    cur=con.execute('INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)',(username,email,digest,int(time.time())))
                    user_id=cur.lastrowid
            except sqlite3.IntegrityError:
                self.page('signup',error='이미 사용 중인 아이디 또는 이메일입니다.',values=values,csrf=csrf,status=409);return
            self.create_session(user_id)
            return
        else:
            identifier=form.get('identifier','').strip()
            password=form.get('password','')
            if len(identifier)>254 or len(password)>128 or not identifier or not password:
                self.page('login',error='아이디와 비밀번호를 확인해 주세요.',values={'identifier':identifier},csrf=csrf,status=400);return
            with db_conn() as con:
                found=con.execute('SELECT id,password_hash FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE LIMIT 1',(identifier,identifier)).fetchone()
            # Constant-cost verification for unknown usernames helps avoid obvious timing differences.
            if found:
                ok=check_password(password,found['password_hash'])
            else:
                ok=check_password(password, 'pbkdf2_sha256$310000$'+'00'*16+'$'+'00'*32)
            if not found or not ok:
                self.page('login',error='아이디 또는 비밀번호가 올바르지 않습니다.',values={'identifier':identifier},csrf=csrf,status=401);return
            self.create_session(found['id'])

    def create_session(self,user_id):
        token=secrets.token_hex(32)
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        csrf=secrets.token_urlsafe(32)
        with db_conn() as con:
            con.execute('DELETE FROM sessions WHERE expires_at<=?',(int(time.time()),))
            con.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',
                        (token_hash,user_id,csrf,int(time.time())+SESSION_LIFETIME))
        self.redirect('/account',cookies=[self.cookie_header('session',token,age=SESSION_LIFETIME),self.cookie_header('guest_csrf','',age=0,clear=True)])


def main():
    if len(sys.argv)>1:
        if sys.argv[1:] == ['create-admin']:
            raise SystemExit(create_admin())
        if sys.argv[1:] == ['change-admin-password']:
            raise SystemExit(change_admin_password())
        print('사용법: python app.py [create-admin|change-admin-password]');raise SystemExit(2)
    init_db()
    bootstrap_admin_from_env()
    bootstrap_admin_from_seed()
    host=os.environ.get('HOST','127.0.0.1')
    port=int(os.environ.get('PORT','8000'))
    server=ThreadingHTTPServer((host,port),Handler)
    print(f'Nexus 사이트: http://{host}:{port}/')
    if not PRODUCTION:
        print('개발 실행: 공개 운영 시 APP_ENV=production, APP_SECRET, DATA_DIR, HTTPS를 설정하세요.')
    try:server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

if __name__=='__main__':main()
