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

# 클린코드 기반 리뷰어 프롬프트 - AI가 언어별로 동적 분석
def get_dynamic_reviewer_prompts(language, framework):
    """AI가 언어/프레임워크별 동적 분석하도록 프롬프트 생성"""

    return {
        "positive": f"""당신은 "격려" 리뷰어입니다.

**언어/프레임워크**: {language}/{framework}
**요구사항**: {{requirements}}
**실제 변경된 코드**:
{{diff_analysis}}

위 {language}/{framework} 코드 변경사항을 분석해서 **잘한 부분을 구체적으로 칭찬**하세요.
- {language}의 모범사례와 {framework}의 패턴 활용도 평가
- 실제 코드 라인을 인용하여 구체적 예시 포함
- 30자 내외로 간결하게 작성
- "예시: 함수명이 명확함 → getUserInfo()" 형태로 구체적 예시 필수
""",

        "neutral": f"""당신은 "분석" 리뷰어입니다.

**언어/프레임워크**: {language}/{framework}
**요구사항**: {{requirements}}
**실제 변경된 코드**:
{{diff_analysis}}

위 {language}/{framework} 코드 변경사항의 **트레이드오프를 객관적 분석**하세요.
- {language} 언어 특성과 {framework} 설계 원칙 관점에서 평가
- 성능 vs 가독성, 복잡도 vs 유지보수성 등 균형점 분석
- 30자 내외로 간결하게 작성
- "예시: 함수 분리로 가독성↑ 성능↓" 형태로 구체적 예시 필수
""",

        "critical": f"""당신은 "지적" 리뷰어입니다.

**언어/프레임워크**: {language}/{framework}
**요구사항**: {{requirements}}
**실제 변경된 코드**:
{{diff_analysis}}

위 {language}/{framework} 코드에서 **개선이 필요한 부분을 엄격히 지적**하세요.
- {language} 모범사례 위반과 {framework} 안티패턴 감지
- 실제 코드를 인용하여 구체적 개선 방안 제시
- 30자 내외로 간결하게 작성
- "예시: 50라인 함수 → 3개로 분리 필요" 형태로 구체적 예시 필수
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

# 언어/프레임워크 감지 및 분석
def analyze_project_info(payload):
    """프로젝트 정보를 분석하여 언어, 프레임워크, 변경사항을 파악"""
    repo = payload.get("repository", {})
    pr = payload.get("pull_request", {})

    # 기본 정보 추출
    language = repo.get("language", "Unknown")
    description = repo.get("description", "")
    branch_name = pr.get("head", {}).get("ref", "")

    # 프레임워크 감지
    framework = "Unknown"
    if "fastapi" in description.lower():
        framework = "FastAPI"
    elif "django" in description.lower():
        framework = "Django"
    elif "flask" in description.lower():
        framework = "Flask"
    elif "react" in description.lower():
        framework = "React"
    elif "vue" in description.lower():
        framework = "Vue.js"
    elif "angular" in description.lower():
        framework = "Angular"

    # 변경사항 분석
    changes = {
        "commits": pr.get("commits", 0),
        "additions": pr.get("additions", 0),
        "deletions": pr.get("deletions", 0),
        "changed_files": pr.get("changed_files", 0)
    }

    return {
        "language": language,
        "framework": framework,
        "branch": branch_name,
        "changes": changes,
        "description": description
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

def analyze_diff_content(files, language, framework):
    """실제 diff 내용을 간단하게 정리 - AI가 분석하도록"""
    diff_analysis = []

    for file in files[:3]:  # 최대 3개 파일
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        additions = file.get("additions", 0)
        deletions = file.get("deletions", 0)

        if not patch:
            continue

        # 실제 언어와 프레임워크 감지
        actual_language = detect_language_from_file(filename)
        actual_framework = detect_framework_from_patch(patch, actual_language)

        # diff의 핵심 변경사항만 추출 (+ 라인들)
        added_lines = []
        for line in patch.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                code_line = line[1:].strip()
                if code_line and not code_line.startswith('#') and not code_line.startswith('//'):
                    added_lines.append(code_line)

        # 파일별 요약
        file_summary = f"""**{filename}** ({actual_language}/{actual_framework}) (+{additions}/-{deletions}):
주요 변경사항:
{chr(10).join(added_lines[:5])}"""  # 최대 5개 라인만

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

    # 🎯 실제 diff 내용 상세 분석 (언어/프레임워크 특화)
    diff_analysis = analyze_diff_content(files, project_info["language"], project_info["framework"])
    _LOGGER.info(f"실제 diff 분석 완료: {len(diff_analysis)} 문자")

    # 각 리뷰어별 AI 분석
    ai_reviews = {}

    for reviewer_type, prompt_template in get_dynamic_reviewer_prompts(project_info["language"], project_info["framework"]).items():
        try:
            prompt = prompt_template.format(
                requirements=requirements,
                diff_analysis=diff_analysis,  # 🔥 실제 변경사항 분석 결과 전달
                language=project_info["language"],
                framework=project_info["framework"],
                branch=project_info["branch"],
                changed_files=project_info["changes"]["changed_files"],
                additions=project_info["changes"]["additions"],
                deletions=project_info["changes"]["deletions"]
            )

            response = await llm.ainvoke([SystemMessage(content=prompt)])
            ai_reviews[reviewer_type] = response.content

        except Exception as e:
            _LOGGER.error(f"AI 리뷰 생성 실패 ({reviewer_type}): {str(e)}")
            ai_reviews[reviewer_type] = f"🚨 AI 분석 중 오류가 발생했습니다: {str(e)[:100]}"

    return ai_reviews

# 3명의 리뷰어 페르소나 정의 (AI 강화 버전)
async def generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements):
    """AI를 활용한 3명의 리뷰어 피드백 생성 - 간결 버전"""
    # AI 분석 실행 (요구사항 포함)
    ai_reviews = await analyze_files_with_ai(files, project_info, repo_name, token, requirements)

    # 격려 (긍정형) - 클린코드 전문가
    positive_review = f"""## ✅ 격려
{ai_reviews['positive']}"""

    # 분석 (중립형) - 리팩토링 전문가
    neutral_review = f"""## ⚖️ 분석
{ai_reviews['neutral']}"""

    # 지적 (비판형) - 코드 품질 감시자
    critical_review = f"""## 🚨 지적
{ai_reviews['critical']}"""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

def extract_requirements_from_pr(payload):
    """PR 제목, 본문에서 요구사항 추출"""
    pr = payload.get("pull_request", {})

    title = pr.get("title", "")
    body = pr.get("body", "") or ""

    # 요구사항 관련 키워드들
    requirement_keywords = [
        "요구사항", "requirement", "구현", "implement", "추가", "add",
        "수정", "fix", "개선", "improve", "변경", "change", "기능", "feature",
        "버그", "bug", "이슈", "issue", "문제", "problem", "리팩토링", "refactor"
    ]

    # 요구사항 추출
    requirements = []

    # 제목에서 추출 (항상 포함)
    if title.strip():
        requirements.append(f"제목: {title}")

    # 본문에서 요구사항 추출
    if body:
        for line in body.split('\n')[:5]:  # 처음 5줄만
            line = line.strip()
            if line and any(keyword in line.lower() for keyword in requirement_keywords):
                requirements.append(f"설명: {line[:80]}")
                break

    # 기본값 처리 - 빈 경우 자동 생성
    if not requirements or not any(req.strip() for req in requirements):
        requirements = [f"기본작업: 코드 개선 및 수정"]

    result = " | ".join(requirements[:2])  # 최대 2개만

    # 빈 문자열 방지
    return result if result.strip() else "기본작업: 코드 품질 개선"

# 클린코드 기반 코드 리뷰 작성 (신규)
async def create_code_review_with_requirements(repo_name, pr_number, files, token, project_info, requirements):
    """클린코드 기반 코드 리뷰 작성"""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 🎯 클린코드 기반 3명의 리뷰어 피드백 생성
    feedback = await generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements)

    # 📍 클린코드 기반 인라인 코멘트 생성
    line_comments = parse_diff_and_get_line_comments(files, feedback)
    _LOGGER.info(f"생성된 클린코드 인라인 코멘트: {len(line_comments)}개")

    # 전체 리뷰 본문 (간결 버전)
    review_body = f"""# 🧹 클린코드 리뷰

**요구사항:** {requirements}

**변경사항:** {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']} 라인

---

{feedback['positive']}

---

{feedback['neutral']}

---

{feedback['critical']}

---

💡 각 변경된 라인에 격려/분석/지적의 클린코드 피드백이 달렸습니다."""

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
            _LOGGER.info(f"PR #{pr_number}에 클린코드 리뷰 작성 완료")
            return True
    except Exception as e:
        _LOGGER.error(f"클린코드 리뷰 작성 실패: {str(e)}")
        return False

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

        # 🎯 PR 요구사항 추출 (필수!)
        requirements = extract_requirements_from_pr(payload)
        _LOGGER.info(f"추출된 요구사항: {requirements}")

        # 프로젝트 정보 분석
        project_info = analyze_project_info(payload)
        _LOGGER.info(f"프로젝트 분석 완료: {project_info['language']}/{project_info['framework']}")

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

        # 🔄 클린코드 기반 코드 리뷰 작성 (신규!)
        success = await create_code_review_with_requirements(
            repo_name, pr_number, files, token, project_info, requirements
        )

        if success:
            _LOGGER.info("Robert/Martin/Kent 클린코드 리뷰 작성 성공")
        else:
            _LOGGER.error("리뷰 작성 실패")

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

def parse_diff_and_get_line_comments(files, ai_reviews):
    """diff를 파싱해서 실제 변경된 라인에 달 코멘트들을 생성 - AI 기반 간소화"""
    line_comments = []

    for file in files[:3]:  # 최대 3개 파일만
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        # 지원하는 파일 확장자 확장
        supported_extensions = ('.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.dart', '.go', '.rs', '.cpp', '.c', '.cs', '.php', '.rb', '.swift', '.kt')
        if not patch or not filename.endswith(supported_extensions):
            continue

        # 언어/프레임워크 감지
        language = detect_language_from_file(filename)
        framework = detect_framework_from_patch(patch, language)

        # diff 헤더에서 라인 정보 파싱
        lines = patch.split('\n')
        current_line_number = None
        comment_count = 0  # 파일당 코멘트 수 제한

        for i, line in enumerate(lines):
            # @@ -old_start,old_count +new_start,new_count @@ 형태 파싱
            if line.startswith('@@'):
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_number = int(match.group(1))
                continue

            # 실제 변경된 라인들 분석 (중요한 라인만)
            if line.startswith('+') and not line.startswith('+++') and comment_count < 5:
                added_line = line[1:].strip()  # + 제거

                # 의미있는 코드 라인만 코멘트 (빈 라인, 주석, 괄호만 있는 라인 제외)
                if (added_line and
                    not added_line.startswith(('#', '//', '/*', '*', '{', '}', ')', '(')) and
                    len(added_line) > 10):

                    # 리뷰어 이름을 순환하면서 할당
                    reviewer_names = ["격려", "분석", "지적"]
                    reviewer_name = reviewer_names[comment_count % 3]

                    # 간단한 코멘트 생성 (AI 리뷰 내용 활용하거나 기본 메시지)
                    comment = generate_simple_line_comment(added_line, language, framework, reviewer_name)

                    # GitHub API용 코멘트 데이터 생성
                    line_comments.append({
                        "path": filename,
                        "line": current_line_number if current_line_number else 1,
                        "body": f"**{reviewer_name}**: {comment}"
                    })

                    comment_count += 1

                # 라인 번호 증가
                if current_line_number:
                    current_line_number += 1

            elif line.startswith(' '):  # 컨텍스트 라인
                if current_line_number:
                    current_line_number += 1

    return line_comments

def generate_simple_line_comment(code_line, language, framework, reviewer_type):
    """간단한 라인 코멘트 생성 - AI에게 맡기는 대신 기본적인 패턴 매칭"""

    # 일반적인 좋은 패턴들
    good_patterns = {
        'def ': f"{language} 함수 정의 좋음. 예시: 네이밍 명확",
        'class ': f"{language} 클래스 구조 적절. 예시: 객체지향 원칙",
        'async ': f"비동기 처리 패턴 적절. 예시: {framework} 모범사례",
        'import ': f"의존성 관리 좋음. 예시: 필요한 모듈만",
        'const ': f"상수 선언 명확. 예시: 불변성 보장",
        '= ': f"변수 할당 적절. 예시: 의미있는 변수명"
    }

    # 개선이 필요한 패턴들
    improvement_patterns = {
        'long_line': f"라인이 길어요. 예시: {len(code_line)}자 → 80자 이하 권장",
        'complex': f"복잡도 확인 필요. 예시: 함수 분리 고려",
        'magic_number': f"Magic Number 발견. 예시: 상수로 추출"
    }

    # 패턴 매칭
    for pattern, comment in good_patterns.items():
        if pattern in code_line.lower():
            return comment

    # 라인 길이 체크
    if len(code_line) > 80:
        return improvement_patterns['long_line']

    # 숫자 리터럴 체크
    if any(num in code_line for num in ['100', '200', '500', '1000']):
        return improvement_patterns['magic_number']

    # 기본 코멘트
    return f"{language} 코드 개선 좋음. 예시: {framework} 패턴 활용"