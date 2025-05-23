# 웹훅 서명 검증 함수
import hashlib
import hmac
import logging
import time
import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from langchain_openai import ChatOpenAI
from langchain.schema import  SystemMessage
from dotenv import load_dotenv

load_dotenv()

from src.config.settings import GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, OPENAI_API_KEY

_LOGGER = logging.getLogger(__name__)

def load_private_key_safely():
    """Private Key를 cryptography 라이브러리로 안전하게 로드"""
    if not GITHUB_APP_PRIVATE_KEY:
        return None

    try:
        # PEM 형식의 private key를 로드
        private_key = serialization.load_pem_private_key(
            GITHUB_APP_PRIVATE_KEY.encode('utf-8'),
            password=None
        )
        _LOGGER.info("✅ Private Key 로드 성공")
        return private_key
    except Exception as e:
        _LOGGER.error(f"❌ Private Key 로드 실패: {str(e)}")
        return None

# Private Key 검증
PRIVATE_KEY_OBJECT = load_private_key_safely()

# OpenAI LLM 초기화
try:
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0.3
    ) if OPENAI_API_KEY else None
except Exception as e:
    _LOGGER.warning(f"OpenAI 초기화 실패: {str(e)}")
    llm = None

# AI 기반 동적 분석 프롬프트
def get_dynamic_reviewer_prompts():
    """AI가 언어/프레임워크를 감지하고 동적 분석하도록 프롬프트 생성"""

    return {
        "positive": """당신은 "격려" 리뷰어입니다.

**요구사항**: {requirements}

**실제 변경된 코드**:
{diff_analysis}

위 코드를 분석해서:
1. 먼저 파일 확장자와 코드 내용으로 언어/프레임워크를 정확히 감지하세요
2. 해당 언어/프레임워크에 특화된 모범사례 관점에서 **잘한 부분을 구체적으로 칭찬**하세요
3. 실제 변경된 코드 라인을 인용하여 구체적 예시 포함
4. 30자 내외로 간결하게 작성
5. "예시: async def handle_request() → 비동기 처리 명확" 형태로 실제 코드 예시 필수
""",

        "neutral": """당신은 "분석" 리뷰어입니다.

**요구사항**: {requirements}

**실제 변경된 코드**:
{diff_analysis}

위 코드를 분석해서:
1. 먼저 파일 확장자와 코드 내용으로 언어/프레임워크를 정확히 감지하세요
2. 해당 언어/프레임워크 특성 관점에서 **트레이드오프를 객관적 분석**하세요
3. 성능 vs 가독성, 복잡도 vs 유지보수성 등 균형점 분석
4. 30자 내외로 간결하게 작성
5. "예시: 함수 분리로 가독성↑ 성능↓" 형태로 구체적 예시 필수
""",

        "critical": """당신은 "지적" 리뷰어입니다.

**요구사항**: {requirements}

**실제 변경된 코드**:
{diff_analysis}

위 코드를 분석해서:
1. 먼저 파일 확장자와 코드 내용으로 언어/프레임워크를 정확히 감지하세요
2. 해당 언어/프레임워크 모범사례 위반과 안티패턴을 **엄격히 지적**하세요
3. 실제 변경된 코드를 인용하여 구체적 개선 방안 제시
4. 30자 내외로 간결하게 작성
5. "예시: 50라인 함수 → 3개로 분리 필요" 형태로 구체적 예시 필수
"""
    }

def validate_github_private_key():
    """GitHub App Private Key 형식을 검증하고 정보를 출력"""
    if not GITHUB_APP_PRIVATE_KEY:
        _LOGGER.error("❌ GitHub App Private Key가 설정되지 않았습니다")
        return False

    key = GITHUB_APP_PRIVATE_KEY.strip()

    # PEM 형식 검증
    if key.startswith("-----BEGIN PRIVATE KEY-----"):
        _LOGGER.info("✅ PKCS#8 형식의 Private Key 감지됨")
        return True
    elif key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
        _LOGGER.info("✅ RSA 형식의 Private Key 감지됨")
        return True
    elif key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
        _LOGGER.error("❌ OpenSSH 형식은 지원되지 않습니다. GitHub App은 RSA/PKCS#8 형식이 필요합니다")
        return False
    else:
        _LOGGER.error(f"❌ 인식할 수 없는 Private Key 형식: {key[:50]}...")
        return False

# 애플리케이션 시작 시 검증
if not validate_github_private_key():
    _LOGGER.warning("⚠️ GitHub App Private Key 설정을 확인해주세요")
    _LOGGER.warning("💡 현재 SSH fingerprint가 설정되어 있습니다. 실제 RSA private key가 필요합니다.")
    _LOGGER.warning("🔗 GitHub App 설정 페이지에서 'Generate a private key'를 클릭하여 .pem 파일을 다운로드하세요.")

# 설치 토큰 발급 함수
async def get_installation_token(installation_id):
    try:
        # 설정 검증
        if not GITHUB_APP_PRIVATE_KEY:
            _LOGGER.error("GitHub App Private Key가 설정되지 않았습니다")
            return None

        if not GITHUB_APP_ID:
            _LOGGER.error("GitHub App ID가 설정되지 않았습니다")
            return None

        # JWT 생성
        _LOGGER.info("JWT 생성 시작")
        now = int(time.time())
        payload = {
            "iat": now,
            "exp": now + 600,  # 10분 유효
            "iss": int(GITHUB_APP_ID)  # App ID는 정수여야 함
        }

        # JWT 서명
        try:
            jwt_token = jwt.encode(payload, GITHUB_APP_PRIVATE_KEY, algorithm="RS256")
            _LOGGER.info("JWT 서명 완료")
        except Exception as e:
            _LOGGER.error(f"JWT 서명 실패: {str(e)}")
            return None

        # 설치 토큰 요청
        _LOGGER.info("설치 토큰 요청 시작")
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers)

            if response.status_code != 201:
                _LOGGER.error(f"토큰 요청 실패: {response.status_code} - {response.text}")
                return None

            _LOGGER.info("설치 토큰 요청 완료")
            return response.json().get("token")

    except Exception as e:
        _LOGGER.error(f"토큰 발급 오류: {str(e)}", exc_info=True)
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

# 언어/프레임워크 감지 및 분석 - AI 위임
def analyze_project_info(payload):
    """프로젝트 기본 정보만 추출 - 언어/프레임워크는 AI가 감지"""
    repo = payload.get("repository", {})
    pr = payload.get("pull_request", {})

    # 변경사항 통계만 추출 (AI가 나머지 분석)
    changes = {
        "commits": pr.get("commits", 0),
        "additions": pr.get("additions", 0),
        "deletions": pr.get("deletions", 0),
        "changed_files": pr.get("changed_files", 0)
    }

    return {
        "language": "AI가 감지",  # AI가 동적으로 감지
        "framework": "AI가 감지",  # AI가 동적으로 감지
        "branch": pr.get("head", {}).get("ref", ""),
        "changes": changes,
        "description": repo.get("description", "")
    }

async def get_file_content(repo_name, file_path, token, sha=None):
    """GitHub API를 통해 파일 내용을 가져옴"""
    url = f"https://api.github.com/repos/{repo_name}/contents/{file_path}"
    if sha:
        url += f"?ref={sha}"

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                import base64
                content = response.json().get("content", "")
                return base64.b64decode(content).decode('utf-8')
            return None
    except Exception as e:
        _LOGGER.error(f"파일 내용 가져오기 실패 {file_path}: {str(e)}")
        return None

def analyze_diff_content(files):
    """실제 diff 내용을 AI가 분석하도록 간단 정리"""
    diff_analysis = []

    for file in files[:3]:  # 최대 3개 파일
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        additions = file.get("additions", 0)
        deletions = file.get("deletions", 0)

        if not patch:
            continue

        # diff의 핵심 변경사항만 추출
        added_lines = []
        removed_lines = []

        for line in patch.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                code_line = line[1:].strip()
                if code_line and not code_line.startswith('#') and not code_line.startswith('//'):
                    added_lines.append(code_line)
            elif line.startswith('-') and not line.startswith('---'):
                code_line = line[1:].strip()
                if code_line and not code_line.startswith('#') and not code_line.startswith('//'):
                    removed_lines.append(code_line)

        # 파일별 요약 (AI가 모든 것을 감지하도록)
        file_summary = f"""**{filename}** (+{additions}/-{deletions}):

추가된 코드:
{chr(10).join(added_lines[:8])}

제거된 코드:
{chr(10).join(removed_lines[:3])}"""

        diff_analysis.append(file_summary)

    return "\n\n".join(diff_analysis) if diff_analysis else "변경사항 분석 결과가 없습니다."

def detect_language_from_file(filename):
    """파일 확장자로 언어 감지"""
    extension_map = {
        '.py': 'Python',
        '.java': 'Java',
        '.kt': 'Kotlin',
        '.js': 'JavaScript',
        '.jsx': 'JavaScript',
        '.ts': 'TypeScript',
        '.tsx': 'TypeScript',
        '.dart': 'Dart',
        '.go': 'Go',
        '.rs': 'Rust',
        '.cpp': 'C++',
        '.c': 'C',
        '.cs': 'C#',
        '.php': 'PHP',
        '.rb': 'Ruby',
        '.swift': 'Swift'
    }

    for ext, lang in extension_map.items():
        if filename.endswith(ext):
            return lang
    return 'Unknown'

def detect_framework_from_patch(patch, language):
    """패치 내용으로 프레임워크 감지"""
    patch_lower = patch.lower()

    if language == 'Python':
        if 'fastapi' in patch_lower or '@app.' in patch_lower:
            return 'FastAPI'
        elif 'django' in patch_lower or 'models.Model' in patch:
            return 'Django'
        elif 'flask' in patch_lower or '@app.route' in patch:
            return 'Flask'
        return 'Python'

    elif language in ['JavaScript', 'TypeScript']:
        if 'react' in patch_lower or 'jsx' in patch_lower or 'usestate' in patch_lower:
            return 'React'
        elif 'vue' in patch_lower or 'computed' in patch_lower:
            return 'Vue'
        elif 'angular' in patch_lower or '@component' in patch_lower:
            return 'Angular'
        elif 'express' in patch_lower or 'app.get' in patch_lower:
            return 'Express'
        return 'JavaScript'

    elif language == 'Java':
        if '@springboot' in patch_lower or '@restcontroller' in patch_lower or 'springbootapplication' in patch_lower:
            return 'Spring Boot'
        elif '@controller' in patch_lower or '@service' in patch_lower:
            return 'Spring'
        return 'Java'

    elif language == 'Dart':
        if 'flutter' in patch_lower or 'widget' in patch_lower or 'statelesswidget' in patch_lower:
            return 'Flutter'
        return 'Dart'

    return language

async def analyze_files_with_ai(files, project_info, repo_name, token, requirements):
    """AI를 활용하여 변경된 파일들을 분석"""
    if not llm:
        return {
            "positive": "✅ AI 분석을 위한 OpenAI API 키가 설정되지 않았습니다.",
            "neutral": "📊 수동 리뷰가 필요합니다.",
            "critical": "⚠️ AI 코드 분석이 비활성화되어 있습니다."
        }

    # 🎯 실제 diff 내용 분석 (AI가 모든 것을 동적으로)
    diff_analysis = analyze_diff_content(files)
    _LOGGER.info(f"실제 diff 분석 완료: {len(diff_analysis)} 문자")

    # 각 리뷰어별 AI 분석 (AI가 모든 언어/프레임워크 감지 담당)
    ai_reviews = {}

    for reviewer_type, prompt_template in get_dynamic_reviewer_prompts().items():
        try:
            prompt = prompt_template.format(
                requirements=requirements,
                diff_analysis=diff_analysis
            )

            response = await llm.ainvoke([SystemMessage(content=prompt)])
            ai_reviews[reviewer_type] = response.content

        except Exception as e:
            _LOGGER.error(f"AI 리뷰 생성 실패 ({reviewer_type}): {str(e)}")
            ai_reviews[reviewer_type] = f"🚨 AI 분석 중 오류가 발생했습니다: {str(e)[:100]}"

    return ai_reviews

# 3명의 리뷰어 페르소나 정의 (AI 강화 버전)
async def generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements):
    """AI를 활용한 3명의 리뷰어 피드백 생성 - AI 완전 위임 버전"""
    # AI 분석 실행 (모든 분석을 AI가 담당)
    ai_reviews = await analyze_files_with_ai(files, project_info, repo_name, token, requirements)

    # 격려 (긍정형) - AI가 모든 것을 감지 후 분석
    positive_review = f"""## ✅ 격려
{ai_reviews['positive']}"""

    # 분석 (중립형) - AI가 모든 것을 감지 후 분석
    neutral_review = f"""## ⚖️ 분석
{ai_reviews['neutral']}"""

    # 지적 (비판형) - AI가 모든 것을 감지 후 분석
    critical_review = f"""## 🚨 지적
{ai_reviews['critical']}"""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

# AI 기반 코드 리뷰 작성 (신규)
async def create_code_review_with_requirements(repo_name, pr_number, files, token, project_info, requirements):
    """AI 완전 위임 기반 코드 리뷰 작성"""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 🎯 AI 완전 위임 기반 3명의 리뷰어 피드백 생성
    feedback = await generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements)

    # 📍 AI 기반 인라인 코멘트 생성
    line_comments = await generate_ai_line_comments(files, requirements)
    _LOGGER.info(f"생성된 AI 인라인 코멘트: {len(line_comments)}개")

    # 전체 리뷰 본문 (AI 기반)
    review_body = f"""# 🤖 AI 코드 리뷰

**요구사항:** {requirements}

**변경사항:** {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']} 라인

---

{feedback['positive']}

---

{feedback['neutral']}

---

{feedback['critical']}

---

💡 각 변경된 라인에 AI가 언어/프레임워크를 감지하여 특화된 피드백을 제공했습니다."""

    # GitHub API 리뷰 데이터
    review_data = {
        "body": review_body,
        "event": "COMMENT",
        "comments": line_comments
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=review_data)
            response.raise_for_status()
            _LOGGER.info(f"PR #{pr_number}에 AI 기반 코드 리뷰 작성 완료")
            return True
    except Exception as e:
        _LOGGER.error(f"AI 코드 리뷰 작성 실패: {str(e)}")
        return False

def verify_webhook_signature(payload_body, signature_header, secret):
    if not signature_header:
        return False

    hash_object = hmac.new(secret.encode('utf-8'),
                           msg=payload_body,
                           digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def extract_requirements_from_pr(payload):
    """PR 제목, 본문에서 요구사항 추출 - AI 처리를 위한 간단 버전"""
    pr = payload.get("pull_request", {})

    title = pr.get("title", "")
    body = pr.get("body", "") or ""

    # 간단하게 제목과 본문 조합
    if title.strip():
        if body.strip():
            return f"제목: {title} | 설명: {body[:100]}"
        else:
            return f"제목: {title}"
    else:
        return "기본작업: 코드 품질 개선"

async def handle_pull_request(payload):
    try:
        _LOGGER.info("풀 리퀘스트 이벤트 처리 시작")

        # 🎯 PR 요구사항 추출 (간소화)
        requirements = extract_requirements_from_pr(payload)
        _LOGGER.info(f"추출된 요구사항: {requirements}")

        # 프로젝트 정보 분석 (기본 정보만, AI가 나머지 분석)
        project_info = analyze_project_info(payload)
        _LOGGER.info(f"프로젝트 분석 완료: 변경파일 {project_info['changes']['changed_files']}개")

        # PR 기본 정보 가져오기
        pr = payload.get("pull_request", {})
        pr_number = pr.get("number")
        repo_name = payload.get("repository", {}).get("full_name")
        installation_id = payload.get("installation", {}).get("id")

        _LOGGER.info(f"PR #{pr_number} 처리 중 - {project_info['changes']['changed_files']}개 파일 변경")

        # 액세스 토큰 발급
        token = await get_installation_token(installation_id)
        if not token:
            _LOGGER.error("토큰 발급 실패")
            return

        # PR 파일 변경사항 가져오기
        files = await get_pr_files(repo_name, pr_number, token)
        _LOGGER.info(f"변경된 파일 {len(files)}개 분석 완료")

        # 🔄 AI 완전 위임 기반 코드 리뷰 작성!
        success = await create_code_review_with_requirements(
            repo_name, pr_number, files, token, project_info, requirements
        )

        if success:
            _LOGGER.info("AI 기반 동적 코드 리뷰 작성 성공")
        else:
            _LOGGER.error("AI 리뷰 작성 실패")

    except Exception as e:
        _LOGGER.error(f"PR 처리 오류: {str(e)}", exc_info=True)

async def handle_pr_notification(payload):
    """PR 관리 관련 액션 처리 (assigned, review_requested 등)"""
    try:
        action = payload.get("action")
        pr = payload.get("pull_request", {})
        pr_number = pr.get("number")
        repo_name = payload.get("repository", {}).get("full_name")
        installation_id = payload.get("installation", {}).get("id")

        _LOGGER.info(f"PR #{pr_number} 알림 처리: {action}")

        # 액세스 토큰 발급
        token = await get_installation_token(installation_id)
        if not token:
            _LOGGER.error("토큰 발급 실패")
            return

        # 액션별 메시지 생성
        if action == "assigned":
            assignee = payload.get("assignee", {}).get("login", "누군가")
            message = f"🎯 **담당자 할당됨**: @{assignee}님이 이 PR의 담당자로 지정되었습니다!"
        elif action == "review_requested":
            reviewer = payload.get("requested_reviewer", {}).get("login", "누군가")
            message = f"👀 **리뷰 요청됨**: @{reviewer}님에게 코드 리뷰가 요청되었습니다!"
        elif action == "ready_for_review":
            message = f"✅ **리뷰 준비 완료**: 이 PR이 리뷰 가능한 상태가 되었습니다!"
        else:
            message = f"📢 **PR 업데이트**: {action} 이벤트가 발생했습니다."

        # 간단한 코멘트 작성
        await post_simple_comment(repo_name, pr_number, token, message)

    except Exception as e:
        _LOGGER.error(f"PR 알림 처리 오류: {str(e)}", exc_info=True)

async def post_simple_comment(repo_name, pr_number, token, message):
    """PR에 간단한 코멘트 작성"""
    url = f"https://api.github.com/repos/{repo_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    comment_data = {
        "body": message
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=comment_data)
            response.raise_for_status()
            _LOGGER.info(f"PR #{pr_number}에 알림 코멘트 작성 완료")
            return True
    except Exception as e:
        _LOGGER.error(f"알림 코멘트 작성 실패: {str(e)}")
        return False

async def generate_ai_line_comments(files, requirements):
    """AI가 실제 변경된 라인별로 정확한 코멘트 생성"""
    if not llm:
        return []

    line_comments = []

    for file in files[:2]:  # 최대 2개 파일만
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        if not patch:
            continue

        # 의미있는 변경 라인들 추출
        significant_changes = []
        lines = patch.split('\n')
        current_line_number = None

        for line in lines:
            if line.startswith('@@'):
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_number = int(match.group(1))
                continue

            if line.startswith('+') and not line.startswith('+++'):
                added_line = line[1:].strip()
                if (added_line and
                    not added_line.startswith(('#', '//', '/*', '*', '{', '}', ')', '(')) and
                    len(added_line) > 15):  # 의미있는 라인만

                    significant_changes.append({
                        'line_number': current_line_number,
                        'code': added_line,
                        'context': line
                    })

                if current_line_number:
                    current_line_number += 1
            elif line.startswith(' '):
                if current_line_number:
                    current_line_number += 1

        # AI에게 각 변경 라인별 코멘트 요청
        if significant_changes:
            try:
                ai_prompt = f"""파일: {filename}
요구사항: {requirements}

다음 변경된 코드 라인들을 분석해서 각각에 대해 정확한 코멘트를 생성하세요:

{chr(10).join([f"라인 {change['line_number']}: {change['code']}" for change in significant_changes[:5]])}

각 라인별로 다음 형태로 응답하세요:
라인 X: [격려/분석/지적] 구체적인 코멘트 (30자 내외) 예시: 실제코드예시

반드시:
1. 파일 확장자와 코드로 언어/프레임워크 감지
2. 해당 기술 스택에 특화된 리뷰
3. 실제 변경된 코드를 정확히 분석
4. 구체적 예시 포함"""

                response = await llm.ainvoke([SystemMessage(content=ai_prompt)])
                ai_comments = response.content

                # AI 응답 파싱해서 GitHub 코멘트 형태로 변환
                for change in significant_changes[:5]:
                    line_num = change['line_number']

                    # AI 응답에서 해당 라인 코멘트 찾기
                    for line in ai_comments.split('\n'):
                        if f"라인 {line_num}:" in line:
                            comment_text = line.replace(f"라인 {line_num}:", "").strip()
                            if comment_text:
                                line_comments.append({
                                    "path": filename,
                                    "line": line_num,
                                    "body": comment_text
                                })
                            break

            except Exception as e:
                _LOGGER.error(f"AI 라인 코멘트 생성 실패: {str(e)}")
                # 실패시 기본 코멘트
                for change in significant_changes[:3]:
                    line_comments.append({
                        "path": filename,
                        "line": change['line_number'],
                        "body": f"**분석**: 코드 변경 감지. 예시: {change['code'][:30]}..."
                    })

    return line_comments