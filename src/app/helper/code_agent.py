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
    "positive": """당신은 "봐"라는 10년차 시니어 개발자입니다. 변경사항의 좋은 점을 찾아 구체적으로 분석하세요.

**PR 요구사항:** {requirements}
프로젝트: {language}/{framework}, 브랜치: {branch}

**코드 변경 분석:**
{diff_analysis}

다음 관점에서 **변경된 코드만** 집중 분석하세요:

**✅ 개선된 점:**
- Before/After 코드 비교하여 좋아진 부분
- 요구사항 충족도 평가
- 코드 품질 향상 사항

**🎯 트레이드오프 분석:**
- 이 변경으로 얻은 이점
- 성능/가독성 개선 효과
- 유지보수성 향상

**💡 추가 제안:**
- 요구사항을 더 잘 만족시키는 방법
- 관련 개선 포인트

실제 diff 코드를 인용하며 긍정적이고 격려하는 톤으로 150자 내외로 작성하세요.""",

    "neutral": """당신은 "드"라는 시스템 아키텍트입니다. 변경사항을 객관적으로 분석하고 균형잡힌 의견을 제시하세요.

**PR 요구사항:** {requirements}
프로젝트: {language}/{framework}, 브랜치: {branch}

**코드 변경 분석:**
{diff_analysis}

다음 기준으로 **변경된 부분만** 객관적 분석하세요:

**📊 변경사항 평가:**
- Before 코드의 문제점
- After 코드의 개선사항
- 요구사항 달성도 측정

**⚖️ 트레이드오프:**
- 얻은 것 vs 잃은 것
- 복잡도 변화 분석
- 성능 영향 평가

**🔧 기술적 제안:**
```python
# 현재 변경사항
기존코드 → 새코드

# 추가 고려사항
더 나은 대안이나 보완점
```

**📈 메트릭스:**
- 코드 라인 수 변화의 의미
- 의존성 변화 영향도

중립적이고 분석적인 톤으로 150자 내외, diff 코드를 구체적으로 인용하여 작성하세요.""",

    "critical": """당신은 "림"이라는 코드 품질 전문가입니다. 변경사항의 문제점과 위험요소를 엄격하게 지적하세요.

**PR 요구사항:** {requirements}
프로젝트: {language}/{framework}, 브랜치: {branch}

**코드 변경 분석:**
{diff_analysis}

다음 위험요소를 **변경된 코드 중심**으로 엄격히 검토하세요:

**🚨 문제점 분석:**
- Before → After 변경으로 생긴 새로운 위험
- 요구사항 미충족 부분
- 잠재적 버그나 side effect

**⚠️ 트레이드오프 문제:**
- 이 변경의 숨겨진 비용
- 기술부채 증가 가능성
- 다른 모듈에 미치는 영향

**🔥 Critical Issues:**
```python
# 문제가 있는 변경
- 기존: safe_code()
+ 신규: risky_code()

# 위험 요소
1. 에러 핸들링 부족
2. 성능 저하 우려
3. 보안 취약점
```

**❌ 즉시 수정 필요:**
- 구체적인 코드 라인과 문제점
- 반드시 해결해야 할 이유
- 대안 제시

비판적이고 엄격한 톤으로 150자 내외, 실제 diff의 문제 코드를 정확히 지적하여 작성하세요."""
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

async def analyze_files_with_ai(files, project_info, repo_name, token, requirements):
    """요구사항 기반 Diff 중심 AI 분석"""
    if not llm:
        return {
            "positive": "✅ AI 분석을 위한 OpenAI API 키가 설정되지 않았습니다.",
            "neutral": "📊 수동 리뷰가 필요합니다.",
            "critical": "⚠️ AI 코드 분석이 비활성화되어 있습니다."
        }

    # Diff 변경사항 상세 분석
    diff_analysis = analyze_diff_changes(files)

    # 각 리뷰어별 AI 분석 (요구사항 + diff 중심)
    ai_reviews = {}

    for reviewer_type, prompt_template in REVIEWER_PROMPTS.items():
        try:
            prompt = prompt_template.format(
                requirements=requirements,
                language=project_info["language"],
                framework=project_info["framework"],
                branch=project_info["branch"],
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
    """AI를 활용한 3명의 리뷰어(긍정, 중립, 부정) 피드백 생성 - 시니어급"""
    language = project_info["language"]
    framework = project_info["framework"]
    changes = project_info["changes"]
    branch = project_info["branch"]

    # AI 분석 실행 (요구사항 포함)
    ai_reviews = await analyze_files_with_ai(files, project_info, repo_name, token, requirements)

    # 📊 변경사항 요약
    change_summary = f"""
**📊 변경사항 요약:**
- **언어/프레임워크:** {language}/{framework}
- **브랜치:** `{branch}`
- **파일:** {changes['changed_files']}개 | **라인:** +{changes['additions']}/-{changes['deletions']}
- **커밋:** {changes['commits']}개
"""

    # 🌟 "봐" (긍정적 리뷰어) - 시니어급 격려
    positive_review = f"""## 🌟 "봐" (시니어 개발자)
{ai_reviews['positive']}

{change_summary}

**🎯 좋은 점:**
- 요구사항 반영이 체계적으로 이루어짐
- Before → After 변경이 논리적으로 구성됨
- 코드 품질과 가독성이 향상됨

**🚀 Next Steps:**
- 추가 테스트 케이스 검토
- 성능 최적화 포인트 확인
- 문서화 업데이트 검토"""

    # ⚖️ "드" (중립적 리뷰어) - 아키텍트급 분석
    neutral_review = f"""## ⚖️ "드" (시스템 아키텍트)
{ai_reviews['neutral']}

{change_summary}

**📐 트레이드오프 분석:**
- **얻은 것:** 요구사항 충족, 코드 개선
- **잃은 것:** 복잡도 증가 가능성
- **영향도:** 다른 모듈에 미치는 파급효과

**🔧 기술적 제안:**
- diff 변경사항의 장기적 영향 검토
- 성능 벤치마크 필요성 평가
- 아키텍처 일관성 유지 확인"""

    # 🔍 "림" (비판적 리뷰어) - 보안 전문가급
    critical_review = f"""## 🔍 "림" (코드 품질 전문가)
{ai_reviews['critical']}

{change_summary}

**🚨 Critical Issues:**
- 요구사항 미반영 부분 존재 여부
- Before → After 변경으로 인한 잠재적 위험
- 예외 처리 및 edge case 고려 부족

**⚡ 즉시 수정 권장:**
- diff에서 발견된 보안 취약점 해결
- 성능 저하 요소 개선
- 코드 품질 표준 준수 확인

**🛡️ 필수 체크리스트:**
- [ ] 요구사항 100% 반영 확인
- [ ] 보안 취약점 제거
- [ ] 성능 테스트 통과"""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

# 요구사항 기반 코드 리뷰 작성 (신규)
async def create_code_review_with_requirements(repo_name, pr_number, files, token, project_info, requirements):
    """요구사항 기반 Diff 중심 코드 리뷰 작성"""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 🎯 요구사항 기반 3명의 리뷰어 피드백 생성
    feedback = await generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements)

    # Diff 변경사항 분석
    diff_summary = analyze_diff_changes(files)

    # 📍 실제 변경된 라인별 인라인 코멘트 생성 (신규!)
    line_comments = parse_diff_and_get_line_comments(files, feedback)
    _LOGGER.info(f"생성된 인라인 코멘트 수: {len(line_comments)}개")

    # 전체 리뷰 본문 작성 (요약용)
    review_body = f"""# 🎯 요구사항 기반 Code Review

> **PR 요구사항:** {requirements}

## 📋 변경사항 개요

| 항목 | 내용 |
|------|------|
| **언어/프레임워크** | {project_info['language']} / {project_info['framework']} |
| **브랜치** | `{project_info['branch']}` |
| **변경사항** | {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']} 라인 |

## 🔄 Diff 분석 결과
{diff_summary}

---

{feedback['positive']}

---

{feedback['neutral']}

---

{feedback['critical']}

---

## 🎯 요구사항 충족도 평가

### ✅ **승인 기준:**
- [ ] 요구사항 100% 반영 완료
- [ ] Critical Issues 해결 완료
- [ ] Before → After 변경사항의 타당성 확인
- [ ] 트레이드오프 분석 및 수용 가능성 검토

### 📝 **Action Items:**
1. **High:** 요구사항 미반영 부분 수정
2. **Medium:** 성능/보안 이슈 해결
3. **Low:** 코드 품질 및 문서화 개선

---

*🔬 각 변경된 라인에 봐/드/림 리뷰어들의 상세 코멘트가 달렸습니다.*
*📧 인라인 코멘트를 확인하여 구체적인 피드백을 받아보세요.*"""

    # GitHub API 리뷰 데이터 (인라인 코멘트 포함)
    review_data = {
        "body": review_body,
        "event": "COMMENT",
        "comments": line_comments  # 실제 diff 라인별 코멘트!
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=review_data)
            response.raise_for_status()
            _LOGGER.info(f"PR #{pr_number}에 요구사항 기반 봐/드/림 리뷰 작성 완료")
            return True
    except Exception as e:
        _LOGGER.error(f"요구사항 기반 리뷰 작성 실패: {str(e)}")
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

        # 🎯 PR 요구사항 추출 (신규)
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

        # 🔄 요구사항 기반 Diff 중심 코드 리뷰 작성 (신규)
        success = await create_code_review_with_requirements(
            repo_name, pr_number, files, token, project_info, requirements
        )

        if success:
            _LOGGER.info("봐/드/림 리뷰어 피드백 작성 성공")
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

def extract_requirements_from_pr(payload):
    """PR 제목, 본문, 코멘트에서 요구사항 추출"""
    pr = payload.get("pull_request", {})

    # PR 제목과 본문에서 요구사항 키워드 찾기
    title = pr.get("title", "")
    body = pr.get("body", "") or ""

    # 요구사항 관련 키워드들
    requirement_keywords = [
        "요구사항", "requirement", "구현", "implement", "추가", "add",
        "수정", "fix", "개선", "improve", "변경", "change", "기능", "feature",
        "버그", "bug", "이슈", "issue", "문제", "problem"
    ]

    # 요구사항 문장 추출
    requirements = []

    # 제목에서 추출
    if any(keyword in title.lower() for keyword in requirement_keywords):
        requirements.append(f"📋 **제목:** {title}")

    # 본문에서 요구사항 추출 (라인별로)
    if body:
        body_lines = body.split('\n')
        for line in body_lines[:10]:  # 처음 10줄만 체크
            line = line.strip()
            if line and any(keyword in line.lower() for keyword in requirement_keywords):
                requirements.append(f"📝 **설명:** {line[:100]}")

    # 요구사항이 없으면 기본값
    if not requirements:
        requirements = [f"📋 **기본 작업:** {title}"]

    return " | ".join(requirements[:3])  # 최대 3개만

def analyze_diff_changes(files):
    """파일별 diff 변경사항을 Before/After로 상세 분석"""
    diff_analysis = []

    for file in files[:3]:  # 최대 3개 파일만 분석
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        additions = file.get("additions", 0)
        deletions = file.get("deletions", 0)
        status = file.get("status", "modified")

        if not patch:
            continue

        # diff를 라인별로 분석
        before_lines = []
        after_lines = []
        context_lines = []

        for line in patch.split('\n')[:30]:  # 최대 30라인
            if line.startswith('-') and not line.startswith('---'):
                before_lines.append(line[1:].strip())
            elif line.startswith('+') and not line.startswith('+++'):
                after_lines.append(line[1:].strip())
            elif not line.startswith('@@') and not line.startswith('+++') and not line.startswith('---'):
                context_lines.append(line.strip())

        # 중요한 변경사항만 필터링
        important_before = [line for line in before_lines[:5]
                           if any(keyword in line for keyword in ['def ', 'class ', 'import ', 'return ', 'if ', 'async '])]
        important_after = [line for line in after_lines[:5]
                          if any(keyword in line for keyword in ['def ', 'class ', 'import ', 'return ', 'if ', 'async '])]

        # 파일별 diff 분석 결과
        file_diff = f"""
### 📁 **{filename}** ({status}, +{additions}/-{deletions})

**🔴 Before (제거됨):**
```python
{chr(10).join(important_before) if important_before else "- 중요한 제거 사항 없음"}
```

**🟢 After (추가됨):**
```python
{chr(10).join(important_after) if important_after else "- 중요한 추가 사항 없음"}
```

**🔄 변경 요약:**
- 제거: {len(before_lines)}라인 | 추가: {len(after_lines)}라인
- 주요변경: {"함수/클래스 정의" if any("def " in line or "class " in line for line in important_after) else "로직 수정"}
"""
        diff_analysis.append(file_diff)

    return "\n".join(diff_analysis) if diff_analysis else """
**📄 변경사항:** 분석 가능한 diff가 없습니다.
- 바이너리 파일이거나 변경사항이 미미할 수 있습니다.
- 설정 파일이나 문서 변경일 가능성이 있습니다.
"""

def parse_diff_and_get_line_comments(files, ai_reviews):
    """diff를 파싱해서 실제 변경된 라인에 달 코멘트들을 생성"""
    line_comments = []

    for file in files[:3]:  # 최대 3개 파일만
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        if not patch or not filename.endswith((".py", ".js", ".ts", ".java", ".go")):
            continue

        # diff 헤더에서 라인 정보 파싱
        lines = patch.split('\n')
        current_line_number = None

        for i, line in enumerate(lines):
            # @@ -old_start,old_count +new_start,new_count @@ 형태 파싱
            if line.startswith('@@'):
                # 예: @@ -49,50 +49,126 @@ def load_private_key_safely():
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_number = int(match.group(1))
                continue

            # 실제 변경된 라인들 분석
            if line.startswith('+') and not line.startswith('+++'):
                added_line = line[1:]  # + 제거

                # 중요한 변경사항만 코멘트 달기
                if any(keyword in added_line for keyword in ['def ', 'class ', 'async ', 'await ', 'import ', 'from ']):

                    # 봐/드/림 중 하나를 랜덤하게 선택해서 해당 라인에 코멘트
                    reviewer_type = ["positive", "neutral", "critical"][i % 3]
                    reviewer_name = {"positive": "봐", "neutral": "드", "critical": "림"}[reviewer_type]

                    # 라인별 맞춤 코멘트 생성
                    if 'def ' in added_line or 'async def' in added_line:
                        if reviewer_type == "positive":
                            comment = f"🌟 **{reviewer_name}**: 함수 정의가 명확하네요! `{added_line.strip()[:50]}...` 좋은 네이밍입니다."
                        elif reviewer_type == "neutral":
                            comment = f"⚖️ **{reviewer_name}**: 함수 복잡도를 고려해보세요. `{added_line.strip()[:50]}...` 단일 책임 원칙은 지켜지고 있나요?"
                        else:
                            comment = f"🔍 **{reviewer_name}**: 에러 핸들링이 빠졌습니다. `{added_line.strip()[:50]}...` try-catch 블록 필요해요."

                    elif 'import ' in added_line or 'from ' in added_line:
                        if reviewer_type == "positive":
                            comment = f"🌟 **{reviewer_name}**: 필요한 라이브러리 추가 좋습니다! `{added_line.strip()}`"
                        elif reviewer_type == "neutral":
                            comment = f"⚖️ **{reviewer_name}**: 의존성 추가 영향도를 검토하세요. `{added_line.strip()}`"
                        else:
                            comment = f"🔍 **{reviewer_name}**: 불필요한 import는 아닌지 확인하세요. `{added_line.strip()}`"

                    elif 'await ' in added_line:
                        if reviewer_type == "positive":
                            comment = f"🌟 **{reviewer_name}**: 비동기 처리 잘 적용했네요! `{added_line.strip()[:50]}...`"
                        elif reviewer_type == "neutral":
                            comment = f"⚖️ **{reviewer_name}**: await 사용 적절한가요? `{added_line.strip()[:50]}...` 성능 영향 체크하세요."
                        else:
                            comment = f"🔍 **{reviewer_name}**: await 에러 처리 누락! `{added_line.strip()[:50]}...` 예외 상황 고려하세요."

                    else:
                        # 일반적인 변경사항
                        if reviewer_type == "positive":
                            comment = f"🌟 **{reviewer_name}**: 코드 개선이 보이네요! `{added_line.strip()[:40]}...`"
                        elif reviewer_type == "neutral":
                            comment = f"⚖️ **{reviewer_name}**: 변경사항 검토: `{added_line.strip()[:40]}...` 사이드 이펙트는 없나요?"
                        else:
                            comment = f"🔍 **{reviewer_name}**: 이 변경이 정말 필요한가요? `{added_line.strip()[:40]}...`"

                    # GitHub API용 코멘트 데이터 생성
                    line_comments.append({
                        "path": filename,
                        "line": current_line_number if current_line_number else 1,
                        "body": comment
                    })

                # 라인 번호 증가
                if current_line_number:
                    current_line_number += 1

            elif line.startswith(' '):  # 컨텍스트 라인
                if current_line_number:
                    current_line_number += 1

    return line_comments