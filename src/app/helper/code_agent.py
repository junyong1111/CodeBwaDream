# 웹훅 서명 검증 함수
import hashlib
import hmac
import logging
import time
import httpx
import jwt

from src.config.settings import GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY

_LOGGER = logging.getLogger(__name__)


# 설치 토큰 발급 함수
async def get_installation_token(installation_id):
    try:
        # JWT 생성
        _LOGGER.info("JWT 생성 시작")
        now = int(time.time())
        payload = {
            "iat": now,
            "exp": now + 600,  # 10분 유효
            "iss": GITHUB_APP_ID
        }

        # JWT 서명
        jwt_token = jwt.encode(payload, GITHUB_APP_PRIVATE_KEY, algorithm="RS256")
        _LOGGER.info("JWT 서명 완료")

        # 설치 토큰 요청
        _LOGGER.info("설치 토큰 요청 시작")
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers)
            response.raise_for_status()
            _LOGGER.info("설치 토큰 요청 완료")
            return response.json().get("token")

    except Exception as e:
        _LOGGER.error(f"토큰 발급 오류: {str(e)}")
        return None

# PR 파일 가져오기
async def get_pr_files(repo_name, pr_number, token):
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

# 간단한 코드 리뷰 작성
async def create_code_review(repo_name, pr_number, files, token):
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    comments = []
    for file in files:
        filename = file.get("filename")
        if filename.endswith(".py"):
            comments.append({
                "path": filename,
                "position": 1,  # 보통 patch의 diff position을 계산해야 함
                "body": "Python 파일이 변경되었습니다. 코드 리뷰를 진행합니다."
            })

    if comments:
        review_data = {
            "body": "자동 코드 리뷰 결과입니다.",
            "event": "COMMENT",
            "comments": comments
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=review_data)
            response.raise_for_status()
            print(f"PR #{pr_number}에 리뷰 작성 완료")

def verify_webhook_signature(payload_body, signature_header, secret):
    if not signature_header:
        return False

    hash_object = hmac.new(secret.encode('utf-8'),
                           msg=payload_body,
                           digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)



async def handle_pull_request(payload):
    try:
        _LOGGER.info("풀 리퀘스트 이벤트 처리 시작")
        # PR 기본 정보 가져오기
        pr = payload.get("pull_request", {})
        pr_number = pr.get("number")
        repo_name = payload.get("repository", {}).get("full_name")
        installation_id = payload.get("installation", {}).get("id")

        _LOGGER.info(f"PR #{pr_number} 처리 중")

        # 액세스 토큰 발급
        token = await get_installation_token(installation_id)
        if not token:
            _LOGGER.error("토큰 발급 실패")
            return

        # PR 파일 변경사항 가져오기
        files = await get_pr_files(repo_name, pr_number, token)

        # 간단한 코드 리뷰 작성
        await create_code_review(repo_name, pr_number, files, token)

    except Exception as e:
        _LOGGER.error(f"PR 처리 오류: {str(e)}")