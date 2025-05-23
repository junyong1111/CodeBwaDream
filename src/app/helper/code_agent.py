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

# 클린코드 기반 리뷰어 프롬프트
REVIEWER_PROMPTS = {
    "positive": """당신은 Robert (클린코드 전문가)입니다. 변경사항에서 클린코드 원칙이 잘 적용된 부분을 찾아 구체적으로 칭찬하세요.

**요구사항:** {requirements}
**변경 분석:** {diff_analysis}

다음 클린코드 관점에서 분석 (30자 내외):
✅ SOLID 원칙 준수도
✅ DRY (중복 제거) 적용
✅ 의미있는 네이밍
✅ 함수 책임의 명확성
✅ 추상화 레벨 일관성

예시: "함수명이 의도를 명확히 표현함. SRP 원칙 잘 지켜짐."
""",

    "neutral": """당신은 Martin (리팩토링 전문가)입니다. 변경사항을 클린코드 관점에서 객관적으로 분석하세요.

**요구사항:** {requirements}
**변경 분석:** {diff_analysis}

다음 관점에서 균형잡힌 분석 (30자 내외):
⚖️ 코드 복잡도 vs 가독성
⚖️ 성능 vs 유지보수성
⚖️ 추상화 vs 구체성
⚖️ 확장성 vs 단순성

예시: "가독성은 향상됐지만 복잡도 증가. 함수 분리 고려 필요."
""",

    "critical": """당신은 Kent (코드 품질 감시자)입니다. 클린코드 원칙 위반 사항을 엄격히 지적하세요.

**요구사항:** {requirements}
**변경 분석:** {diff_analysis}

다음 클린코드 위반사항 점검 (30자 내외):
🚨 Long Method (함수가 너무 긴가?)
🚨 God Object (클래스가 너무 많은 책임을 지는가?)
🚨 Magic Number (의미없는 숫자 사용)
🚨 Duplicate Code (중복 코드 존재)
🚨 Poor Naming (의미불명한 변수/함수명)

예시: "35라인 함수는 너무 김. 3개 이하 함수로 분리 필요."
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

async def analyze_files_with_ai(files, project_info, repo_name, token):
    """AI를 활용하여 변경된 파일들을 분석"""
    if not llm:
        return {
            "positive": "✅ AI 분석을 위한 OpenAI API 키가 설정되지 않았습니다.",
            "neutral": "📊 수동 리뷰가 필요합니다.",
            "critical": "⚠️ AI 코드 분석이 비활성화되어 있습니다."
        }

    # 파일별 상세 분석 - 시니어급 관점
    file_changes = []

    for file in files[:5]:  # 최대 5개 파일 분석
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        additions = file.get("additions", 0)
        deletions = file.get("deletions", 0)
        status = file.get("status", "modified")

        if filename.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c")):
            # 코드 품질 지표 분석
            analysis_points = {
                "functions": [],
                "imports": [],
                "classes": [],
                "security_risks": [],
                "performance_issues": [],
                "architecture_patterns": []
            }

            # 패치에서 중요한 변경사항 추출
            for line_num, line in enumerate(patch.split('\n')[:50], 1):
                line = line.strip()

                # 함수/메서드 정의
                if any(pattern in line for pattern in ['+def ', '+async def', '+function ', '+class ']):
                    analysis_points["functions"].append(f"L{line_num}: {line[:80]}")

                # Import/의존성 변경
                elif any(pattern in line for pattern in ['+import ', '+from ', '+require(', '+#include']):
                    analysis_points["imports"].append(f"L{line_num}: {line[:60]}")

                # 보안 관련 패턴
                elif any(pattern in line.lower() for pattern in ['password', 'secret', 'key', 'token', 'auth']):
                    analysis_points["security_risks"].append(f"L{line_num}: {line[:60]}")

                # 성능 관련 패턴
                elif any(pattern in line for pattern in ['for ', 'while ', 'async ', 'await ', 'query', 'database']):
                    analysis_points["performance_issues"].append(f"L{line_num}: {line[:60]}")

            # 구체적인 분석 결과 생성
            file_summary = f"""
**📁 {filename}** ({status}, +{additions}/-{deletions})

**🔧 주요 변경사항:**
{chr(10).join(analysis_points["functions"][:3]) if analysis_points["functions"] else "- 함수 정의 변경 없음"}

**📦 의존성/Import:**
{chr(10).join(analysis_points["imports"][:3]) if analysis_points["imports"] else "- Import 변경 없음"}

**⚠️ 주의사항:**
{chr(10).join(analysis_points["security_risks"][:2]) if analysis_points["security_risks"] else "- 보안 관련 변경 없음"}

**⚡ 성능 고려사항:**
{chr(10).join(analysis_points["performance_issues"][:2]) if analysis_points["performance_issues"] else "- 성능 관련 변경 없음"}
"""
            file_changes.append(file_summary)

    # 전체 변경사항이 없으면 기본 메시지
    if not file_changes:
        file_changes_text = """
**분석 결과:** 코드 파일 변경사항이 감지되지 않았습니다.
- 문서 파일이나 설정 파일만 변경되었을 수 있습니다.
- 바이너리 파일이나 대용량 파일은 분석에서 제외됩니다.
"""
    else:
        file_changes_text = "\n".join(file_changes)

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
            ai_reviews[reviewer_type] = f"🚨 AI 분석 중 오류가 발생했습니다: {str(e)[:100]}"

    return ai_reviews

# 3명의 리뷰어 페르소나 정의 (AI 강화 버전)
async def generate_reviewer_feedback_with_ai(project_info, files, repo_name, token):
    """AI를 활용한 3명의 리뷰어(긍정, 중립, 부정) 피드백 생성 - 시니어급"""
    language = project_info["language"]
    framework = project_info["framework"]
    changes = project_info["changes"]
    branch = project_info["branch"]

    # AI 분석 실행
    ai_reviews = await analyze_files_with_ai(files, project_info, repo_name, token)

    # 📊 변경사항 요약
    change_summary = f"""
**📊 변경사항 요약:**
- **언어/프레임워크:** {language}/{framework}
- **브랜치:** `{branch}`
- **파일:** {changes['changed_files']}개 | **라인:** +{changes['additions']}/-{changes['deletions']}
- **커밋:** {changes['commits']}개
"""

    # 🌟 Robert (긍정적 리뷰어) - 클린코드 전문가
    positive_review = f"""## ✅ Robert
{ai_reviews['positive']}"""

    # ⚖️ Martin (중립적 리뷰어) - 리팩토링 전문가
    neutral_review = f"""## ⚖️ Martin
{ai_reviews['neutral']}"""

    # 🔍 Kent (비판적 리뷰어) - 코드 품질 감시자
    critical_review = f"""## 🚨 Kent
{ai_reviews['critical']}"""

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
    review_body = f"""# 🤖 Senior-Level Code Review

> **자동 코드 리뷰 v2.0** - AI 기반 3인 리뷰어 분석 결과

## 📋 Pull Request 개요

| 항목 | 내용 |
|------|------|
| **언어/프레임워크** | {project_info['language']} / {project_info['framework']} |
| **브랜치** | `{project_info['branch']}` |
| **변경사항** | {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']} 라인 |
| **커밋수** | {project_info['changes']['commits']}개 |

---

{feedback['positive']}

---

{feedback['neutral']}

---

{feedback['critical']}

---

## 🎯 종합 결론

### ✅ **Approve 조건:**
- [ ] Critical Issues 해결 완료
- [ ] 보안 취약점 점검 완료
- [ ] 성능 테스트 통과
- [ ] 단위 테스트 작성/업데이트

### 📝 **추천 Actions:**
1. **우선순위 High:** 보안 관련 수정사항 적용
2. **우선순위 Medium:** 성능 최적화 검토
3. **우선순위 Low:** 코드 문서화 및 리팩토링

---

*🔬 이 리뷰는 GPT-4o-mini 기반 AI 시스템에 의해 생성되었습니다.*
*📧 추가 문의: 시니어 개발자에게 직접 문의하세요.*"""

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

                    # Robert/Martin/Kent 중 하나를 순환하면서 선택
                    reviewer_names = ["Robert", "Martin", "Kent"]
                    reviewer_name = reviewer_names[i % 3]

                    # 클린코드 기반 실제 변경사항 분석
                    if 'def ' in added_line and len(added_line.strip()) > 80:
                        comments_pool = [
                            f"**{reviewer_name}**: 함수 시그니처가 깔끔함 👍",
                            f"**{reviewer_name}**: 파라미터 5개 이상이면 객체로 묶어보세요",
                            f"**{reviewer_name}**: 함수명이 동사+명사 패턴 좋음"
                        ]
                    elif 'async def' in added_line:
                        comments_pool = [
                            f"**{reviewer_name}**: 비동기 함수명에 'async' 표시 없어도 됨",
                            f"**{reviewer_name}**: 비동기 처리 관심사 분리 잘됨",
                            f"**{reviewer_name}**: 함수 길이 15라인 이하로 유지하세요"
                        ]
                    elif 'class ' in added_line:
                        comments_pool = [
                            f"**{reviewer_name}**: 클래스명 PascalCase 좋음",
                            f"**{reviewer_name}**: 단일 책임 원칙 확인 필요",
                            f"**{reviewer_name}**: 상속보다 컴포지션 고려해보세요"
                        ]
                    elif 'import ' in added_line:
                        comments_pool = [
                            f"**{reviewer_name}**: import 순서: 표준→서드파티→로컬",
                            f"**{reviewer_name}**: 순환 import 위험 체크",
                            f"**{reviewer_name}**: 사용하지 않는 import 정리하세요"
                        ]
                    elif len(added_line.strip()) > 100:
                        comments_pool = [
                            f"**{reviewer_name}**: 한 라인이 너무 김. 80자 이하 권장",
                            f"**{reviewer_name}**: 체이닝보다 중간 변수 사용 고려",
                            f"**{reviewer_name}**: 복잡한 표현식은 함수로 추출하세요"
                        ]
                    elif any(magic in added_line for magic in ['5', '10', '100', '1000']):
                        comments_pool = [
                            f"**{reviewer_name}**: Magic Number 발견. 상수로 정의하세요",
                            f"**{reviewer_name}**: 의미있는 상수명으로 추출 필요",
                            f"**{reviewer_name}**: 하드코딩된 숫자는 설정으로 분리"
                        ]
                    elif 'return ' in added_line and len(added_line.split('return')[1].strip()) > 50:
                        comments_pool = [
                            f"**{reviewer_name}**: 복잡한 return문. 중간 변수 사용 권장",
                            f"**{reviewer_name}**: Early Return 패턴 적용해보세요",
                            f"**{reviewer_name}**: 조건부 반환은 가드 클로즈 사용"
                        ]
                    else:
                        comments_pool = [
                            f"**{reviewer_name}**: 코드 의도가 명확함",
                            f"**{reviewer_name}**: 변수명이 의미를 잘 표현함",
                            f"**{reviewer_name}**: 적절한 추상화 레벨 유지"
                        ]

                    # 리뷰어별로 다른 스타일의 코멘트 선택
                    comment = comments_pool[i % 3]

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