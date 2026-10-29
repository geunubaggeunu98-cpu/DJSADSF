# Nexus — Railway 실운영 서버 배포판 (v33)

이 파일은 **Python 서버·SQLite 데이터베이스 기반의 실제 웹사이트**입니다. HTML 미리보기가 아닙니다. 기존 v32의 회원가입, 로그인, 관리자, 고객지원, 스크롤 애니메이션을 유지합니다.

## 추천: Railway Hobby + Volume

1. ZIP을 **풀어서** 루트 파일들(`Dockerfile`, `app.py`, `templates/`, `entrypoint.py` 등)을 GitHub **비공개** 저장소에 업로드합니다. ZIP 자체를 그대로 업로드하지 마세요.
2. https://railway.com/new 에서 **Deploy from GitHub repo**로 해당 저장소를 선택합니다. 루트의 `Dockerfile`을 자동 감지해 배포합니다.
3. Railway 서비스 **Variables**에서 아래 환경 변수를 설정합니다(관리자 비밀번호/APP_SECRET는 소스나 ZIP에 넣지 마세요).
4. 서비스에 **Volume**을 생성해 **`/data`** 에 마운트합니다. 이 단계가 빠지면 재배포 시 SQLite 회원·상담 기록을 잃을 수 있습니다.
5. 배포가 성공하면 서비스 **Settings → Networking → Generate Domain**을 선택합니다. 도메인은 Railway가 실제로 발급하는 값만 홍보하세요.
6. `/healthz` 접속으로 서버 상태를 확인하고, 관리자 로그인·회원가입·고객지원 테스트를 진행합니다.

## Railway 서비스 변수

| 이름 | 값 |
|---|---|
| `APP_ENV` | `production` |
| `HOST` | `0.0.0.0` |
| `DATA_DIR` | `/data/nexus` |
| `COOKIE_SECURE` | `1` |
| `APP_SECRET` | **새롭게 생성한 임의의 48자 이상 영문/숫자 문자열** (`python -c "import secrets;print(secrets.token_urlsafe(48))"` 로 생성 가능) |
| `NEXUS_ADMIN_USERNAME` | `nexus_admin` |
| `NEXUS_ADMIN_EMAIL` | 운영자가 소유한 본인 이메일 |
| `NEXUS_ADMIN_PASSWORD` | 새롭게 설정한 **14~128자** 강력한 비밀번호, 반드시 Railway 비공개 변수로 입력 |

`PORT`는 Railway가 주입하는 포트를 자동으로 사용합니다. 관리자 비밀번호는 **첫 데이터베이스 생성 때만** 적용됩니다. 기존 DB 사용 시 초기 관리자 변수로 계정이 강제 변경되지 않습니다.

## 보안 및 데이터 유지 주의사항

- 무료 플랜이나 트라이얼은 영구 운영을 보장하지 않습니다. 장기 운영에는 월 최소 비용과 사용량을 확인한 **Hobby** 플랜을 권장합니다.
- 볼륨은 삭제하지 말고 정기적으로 백업하세요. 볼륨을 붙여도 자동 백업을 대신하지 않습니다.
- 인터넷에 공개된 관리자 비밀번호를 재사용하지 마세요. 먼저 비공개 새 비밀번호를 설정하고 운영 후 변경 기능을 이용하세요.
- URL이 열리는 것만으로 모든 기능이 정상인 것은 아닙니다. 관리자·회원 두 계정으로 상담 왕복 테스트를 진행하세요.
- 사이트에 실제 고객 데이터를 저장할 경우 개인정보 보호 및 적절한 안내/정책도 준비해야 합니다.

## 로컬 테스트

```bash
python tests/smoke_test.py
python tests/check_production.py
```

Python 3.12 이상 권장. Docker 이미지는 기동 시 볼륨 권한을 조정하고 `nexus` 일반 사용자 권한으로 서버를 실행합니다.

## 다른 호스팅

Render용 배포판은 이전 v32 ZIP을 사용하세요. Railway용 이 ZIP은 Netlify Drop에서 실제 회원가입·관리자 기능을 실행할 수 없습니다.
