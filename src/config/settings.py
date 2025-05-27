import os
import logging
import base64

from dotenv import load_dotenv

load_dotenv()

_LOGGER = logging.getLogger(__name__)

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

    # PEM 형식 재구성 - 안전한 방법
    if "-----BEGIN" in private_key and "-----END" in private_key:
        lines = private_key.split('\n')
        cleaned_lines = []

        for line in lines:
            line = line.strip()
            if line:  # 빈 줄 제거
                cleaned_lines.append(line)

        # PEM 블록 재구성
        if cleaned_lines:
            # 헤더 찾기
            header_idx = -1
            footer_idx = -1

            for i, line in enumerate(cleaned_lines):
                if line.startswith("-----BEGIN"):
                    header_idx = i
                elif line.startswith("-----END"):
                    footer_idx = i
                    break

            if header_idx >= 0 and footer_idx > header_idx:
                header = cleaned_lines[header_idx]
                footer = cleaned_lines[footer_idx]
                key_content = cleaned_lines[header_idx + 1:footer_idx]

                # 키 내용을 64자씩 줄바꿈
                all_key_content = ''.join(key_content)
                formatted_content = []
                for i in range(0, len(all_key_content), 64):
                    formatted_content.append(all_key_content[i:i+64])

                # PEM 형식으로 재구성
                result = header + '\n' + '\n'.join(formatted_content) + '\n' + footer
                return result

    return None

GITHUB_APP_PRIVATE_KEY = get_github_private_key()
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# --- Code Review Agent Configuration ---
# 최대 분석 파일 수 (전체 PR 리뷰 및 라인 코멘트 생성 시)
MAX_FILES_TO_ANALYZE = int(os.getenv("MAX_FILES_TO_ANALYZE", "3"))
# 파일당 최대 인라인 코멘트 수
MAX_LINE_COMMENTS_PER_FILE = int(os.getenv("MAX_LINE_COMMENTS_PER_FILE", "3"))
# Diff 분석 시 파일당 추가/삭제 라인 수 제한
MAX_ADDED_LINES_PER_FILE_DIFF = int(os.getenv("MAX_ADDED_LINES_PER_FILE_DIFF", "5"))
MAX_REMOVED_LINES_PER_FILE_DIFF = int(os.getenv("MAX_REMOVED_LINES_PER_FILE_DIFF", "3"))
# PR 본문 요약 길이
MAX_PR_BODY_LENGTH_FOR_REQUIREMENTS = int(os.getenv("MAX_PR_BODY_LENGTH_FOR_REQUIREMENTS", "500"))
PR_BODY_SUMMARY_PREFIX_LENGTH = int(os.getenv("PR_BODY_SUMMARY_PREFIX_LENGTH", "250"))
PR_BODY_SUMMARY_SUFFIX_LENGTH = int(os.getenv("PR_BODY_SUMMARY_SUFFIX_LENGTH", "150"))

_LOGGER.info(f"GitHub App ID: {GITHUB_APP_ID}")
_LOGGER.info(f"OpenAI API Key Loaded: {bool(OPENAI_API_KEY)}")
_LOGGER.info(f"Max files to analyze: {MAX_FILES_TO_ANALYZE}")
_LOGGER.info(f"Max line comments per file: {MAX_LINE_COMMENTS_PER_FILE}")
