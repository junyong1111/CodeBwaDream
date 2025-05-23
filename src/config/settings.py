import os
import base64

from dotenv import load_dotenv

load_dotenv()

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")

# GitHub App Private Key 처리 개선
def get_github_private_key():
    """GitHub App Private Key를 올바른 형식으로 파싱"""
    private_key_env = os.getenv("GITHUB_APP_PRIVATE_KEY", "")

    if not private_key_env:
        return None

    # 공백 제거
    private_key_env = private_key_env.strip()

    # Base64로 인코딩된 경우 디코딩 시도
    if not private_key_env.startswith("-----BEGIN"):
        try:
            private_key_env = base64.b64decode(private_key_env).decode('utf-8')
        except Exception:
            pass

    # 줄바꿈 문자 정규화 - 더 강력한 처리
    private_key = private_key_env.replace('\\n', '\n').replace('\\r', '').strip()

    # PEM 형식 검증 및 정규화
    if "-----BEGIN RSA PRIVATE KEY-----" in private_key:
        # RSA 형식은 그대로 유지
        return private_key
    elif "-----BEGIN PRIVATE KEY-----" in private_key:
        # PKCS#8 형식은 그대로 유지
        return private_key
    elif "-----BEGIN OPENSSH PRIVATE KEY-----" in private_key:
        # OpenSSH 형식은 지원하지 않음
        return None
    else:
        # 헤더/푸터 없는 경우 키 내용만 추출하여 재구성
        lines = private_key.split('\n')
        key_lines = [line.strip() for line in lines if line.strip() and not line.startswith('-----')]

        if key_lines:
            key_content = ''.join(key_lines)
            # Base64 검증
            try:
                base64.b64decode(key_content + '==')  # 패딩 추가하여 검증
                return f"-----BEGIN PRIVATE KEY-----\n{key_content}\n-----END PRIVATE KEY-----"
            except Exception:
                return None

        return None

GITHUB_APP_PRIVATE_KEY = get_github_private_key()
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
