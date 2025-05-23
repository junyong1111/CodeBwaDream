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

# 리뷰어 페르소나별 프롬프트 템플릿
REVIEWER_PROMPTS = {
    "positive": """당신은 Alex라는 긍정적이고 격려하는 시니어 개발자입니다.
코드를 리뷰할 때 항상 좋은 점을 먼저 찾고, 개발자를 동기부여시키는 방식으로 피드백을 제공합니다.
이모지를 적절히 사용하고 친근하고 따뜻한 톤으로 작성하세요.

프로젝트 정보:
- 언어: {language}
- 프레임워크: {framework}
- 브랜치: {branch}
- 변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

변경된 파일들:
{file_changes}

좋은 점들을 강조하고 건설적인 제안을 해주세요. 200자 내외로 작성하세요.""",

    "neutral": """당신은 Morgan이라는 분석적이고 객관적인 테크 리드입니다.
코드를 메트릭스와 베스트 프랙티스 관점에서 중립적으로 분석하고 평가합니다.
데이터와 팩트에 기반한 객관적인 피드백을 제공하세요.

프로젝트 정보:
- 언어: {language}
- 프레임워크: {framework}
- 브랜치: {branch}
- 변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

변경된 파일들:
{file_changes}

코드 품질, 구조, 패턴에 대해 객관적으로 분석하고 개선 방향을 제시하세요. 200자 내외로 작성하세요.""",

    "critical": """당신은 Jordan이라는 엄격하고 품질에 집착하는 아키텍트입니다.
코드의 잠재적 문제점, 보안 이슈, 성능 문제를 찾아내는 것이 전문입니다.
높은 기준을 적용하여 개선이 필요한 부분을 구체적으로 지적합니다.

프로젝트 정보:
- 언어: {language}
- 프레임워크: {framework}
- 브랜치: {branch}
- 변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

변경된 파일들:
{file_changes}

코드의 잠재적 위험 요소, 개선 필요사항, 품질 이슈를 엄격하게 검토하세요. 200자 내외로 작성하세요."""
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

async def analyze_files_with_ai(files, project_info, repo_name, token):
    """AI를 활용하여 변경된 파일들을 분석"""
    if not llm:
        return {
            "positive": "✅ AI 분석을 위한 OpenAI API 키가 설정되지 않았습니다.",
            "neutral": "📊 수동 리뷰가 필요합니다.",
            "critical": "⚠️ AI 코드 분석이 비활성화되어 있습니다."
        }

    # 파일별 변경사항 분석
    file_changes = []
    for file in files[:3]:  # 최대 3개 파일만 분석
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        if filename.endswith((".py", ".js", ".ts", ".java")):
            file_changes.append(f"**{filename}**:\n```\n{patch[:500]}...\n```")

    file_changes_text = "\n".join(file_changes) if file_changes else "파일 변경사항을 분석할 수 없습니다."

    # 각 리뷰어별 AI 분석
    ai_reviews = {}

    for reviewer_type, prompt_template in REVIEWER_PROMPTS.items():
        try:
            prompt = prompt_template.format(
                language=project_info["language"],
                framework=project_info["framework"],
                branch=project_info["branch"],
                changed_files=project_info["changes"]["changed_files"],
                additions=project_info["changes"]["additions"],
                deletions=project_info["changes"]["deletions"],
                file_changes=file_changes_text
            )

            response = await llm.ainvoke([SystemMessage(content=prompt)])
            ai_reviews[reviewer_type] = response.content

        except Exception as e:
            _LOGGER.error(f"AI 리뷰 생성 실패 ({reviewer_type}): {str(e)}")
            ai_reviews[reviewer_type] = f"AI 분석 중 오류가 발생했습니다: {str(e)}"

    return ai_reviews

# 3명의 리뷰어 페르소나 정의 (AI 강화 버전)
async def generate_reviewer_feedback_with_ai(project_info, files, repo_name, token):
    """AI를 활용한 3명의 리뷰어(긍정, 중립, 부정) 피드백 생성"""
    language = project_info["language"]
    framework = project_info["framework"]
    changes = project_info["changes"]
    branch = project_info["branch"]

    # AI 분석 실행
    ai_reviews = await analyze_files_with_ai(files, project_info, repo_name, token)

    # 긍정적 리뷰어 (Alex - AI 강화)
    positive_review = f"""## 🌟 긍정적 리뷰 (Alex)

안녕하세요! 멋진 작업이네요! 👏

**프로젝트 분석:**
- **기술 스택**: {language}/{framework} - 훌륭한 선택! 🚀
- **브랜치**: `{branch}` - 깔끔한 기능 개발 브랜치네요
- **변경사항**: {changes['changed_files']}개 파일, +{changes['additions']}/-{changes['deletions']} 라인

**AI 코드 분석:**
{ai_reviews['positive']}

계속해서 이런 좋은 코드를 작성해주세요! 💪"""

    # 중립적 리뷰어 (Morgan - AI 강화)
    neutral_review = f"""## ⚖️ 중립적 리뷰 (Morgan)

코드 변경사항에 대한 기술적 분석입니다.

**메트릭스 분석:**
- 언어: {language} | 프레임워크: {framework}
- 브랜치: {branch}
- 파일: {changes['changed_files']}개 | 라인: +{changes['additions']}/-{changes['deletions']}

**AI 품질 분석:**
{ai_reviews['neutral']}

**권장사항**: 코드 리뷰 후 테스트 및 문서화 업데이트 확인"""

    # 비판적 리뷰어 (Jordan - AI 강화)
    critical_review = f"""## 🔍 비판적 리뷰 (Jordan)

코드 품질 향상을 위한 엄격한 검토입니다.

**위험도 평가:**
- 변경 범위: {changes['changed_files']}개 파일 ({language}/{framework} 스택)
- 코드 증감: +{changes['additions']}/-{changes['deletions']} 라인

**AI 품질 검증:**
{ai_reviews['critical']}

**필수 검토사항:**
⚠️ 단위 테스트 커버리지 | 보안 취약점 스캔 | 성능 최적화 검토

더 엄격한 품질 관리가 필요합니다."""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

# 향상된 코드 리뷰 작성
async def create_code_review(repo_name, pr_number, files, token, project_info):
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 3명의 리뷰어 피드백 생성
    feedback = await generate_reviewer_feedback_with_ai(project_info, files, repo_name, token)

    # 전체 리뷰 본문 작성
    review_body = f"""# 🤖 자동 코드 리뷰 결과

**프로젝트 정보:**
- 언어: {project_info['language']}
- 프레임워크: {project_info['framework']}
- 브랜치: `{project_info['branch']}`
- 변경사항: {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']}

---

{feedback['positive']}

---

{feedback['neutral']}

---

{feedback['critical']}

---

*💡 이 리뷰는 자동으로 생성되었습니다. 추가적인 수동 리뷰를 권장합니다.*"""

    # 파일별 코멘트 생성
    comments = []
    for file in files[:3]:  # 최대 3개 파일에만 코멘트
        filename = file.get("filename", "")
        if filename.endswith((".py", ".js", ".ts", ".java")):
            comments.append({
                "path": filename,
                "position": 1,
                "body": f"📝 **{filename}** 파일이 수정되었습니다. {project_info['language']} 코딩 표준을 준수했는지 확인해주세요."
            })

    review_data = {
        "body": review_body,
        "event": "COMMENT",
        "comments": comments
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=review_data)
            response.raise_for_status()
            _LOGGER.info(f"PR #{pr_number}에 3명 리뷰어 피드백 작성 완료")
            return True
    except Exception as e:
        _LOGGER.error(f"리뷰 작성 실패: {str(e)}")
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

        # 3명 리뷰어의 코드 리뷰 작성
        success = await create_code_review(repo_name, pr_number, files, token, project_info)

        if success:
            _LOGGER.info("3명 리뷰어 피드백 작성 성공")
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