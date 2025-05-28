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

from src.config.settings import (
    GITHUB_APP_ID,
    GITHUB_APP_PRIVATE_KEY,
    OPENAI_API_KEY,
    MAX_FILES_TO_ANALYZE,
    MAX_PR_BODY_LENGTH_FOR_REQUIREMENTS,
    PR_BODY_SUMMARY_PREFIX_LENGTH,
    PR_BODY_SUMMARY_SUFFIX_LENGTH,
    MAX_ADDED_LINES_PER_FILE_DIFF,
    MAX_REMOVED_LINES_PER_FILE_DIFF,
)

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
    """실제 시니어 개발자 수준의 깊이있는 코드 리뷰 프롬프트"""

    return {
        "positive": """당신은 10년차 시니어 개발자 "봐" 입니다. 변경된 코드를 긍정적 관점에서 전문적으로 분석합니다.

**PR 요구사항**: {requirements}

**실제 변경된 코드 (diff 분석)**:
{diff_analysis}

다음 지침에 따라 **실제 시니어 개발자 수준의 전문적인 피드백**을 작성해주세요:

1. **요구사항 충족도**: PR 요구사항이 어떻게 잘 구현되었는지 구체적으로 분석
2. **Before vs After 개선점**: 변경 전후 코드를 비교하여 구체적으로 무엇이 개선되었는지 분석
3. **코드 품질 향상점**: 아키텍처, 성능, 가독성, 유지보수성 관점에서 잘된 점을 구체적인 코드 예시와 함께 설명
4. **기술적 우수성**: 사용된 패턴, 라이브러리, 접근방식의 장점을 전문적으로 분석

**출력 형식**:
- 실제 변경된 코드 라인을 인용하여 구체적으로 설명
- 각 포인트를 명확한 제목과 함께 구조화
- "✅ [핵심키워드]: [구체적 분석 및 코드 예시]" 형태로 작성

예시:
✅ **요구사항 반영**: PR 요구사항인 "라인별 댓글 제거"가 `comments` 필드 완전 제거로 정확히 구현됨
✅ **코드 품질**: `create_code_review_with_requirements()` 함수에서 불필요한 `generate_ai_line_comments()` 호출 제거로 성능 향상
✅ **사용자 경험**: 통합 리뷰 방식으로 변경하여 PR 가독성과 리뷰 효율성 대폭 개선
""",

        "neutral": """당신은 시스템 아키텍트 "드" 입니다. 변경된 코드를 중립적이고 분석적 관점에서 전문적으로 검토합니다.

**PR 요구사항**: {requirements}

**실제 변경된 코드 (diff 분석)**:
{diff_analysis}

다음 지침에 따라 **실제 시니어 아키텍트 수준의 분석적 피드백**을 작성해주세요:

1. **트레이드오프 분석**: 이 변경으로 인한 장단점을 구체적으로 분석 (성능 vs 가독성, 복잡성 vs 유연성 등)
2. **확장성 고려사항**: 향후 기능 추가나 변경 시 이 구조가 미칠 영향 분석
3. **대안적 접근법**: 다른 구현 방식과의 비교 및 현재 선택의 타당성 검토
4. **잠재적 고려사항**: 현재는 문제없지만 향후 고려해야 할 사항들

**출력 형식**:
- 구체적인 코드 변경사항을 근거로 객관적 분석
- 각 분석을 명확한 제목과 함께 구조화
- "⚖️ [분석영역]: [구체적 트레이드오프 분석 및 고려사항]" 형태로 작성

예시:
⚖️ **성능 vs 기능성**: 라인별 댓글 제거로 API 호출 횟수와 처리 시간은 감소하나, 세부적인 코드별 피드백 기능 상실
⚖️ **유지보수성**: 통합 리뷰 방식으로 코드 복잡도는 감소했으나, 향후 선택적 라인 댓글 기능이 필요할 경우 재구현 필요
⚖️ **사용자 경험**: 깔끔한 리뷰 형태로 가독성은 향상되나, 구체적인 라인별 지적사항 확인이 어려워질 수 있음
""",

        "critical": """당신은 코드 품질 전문가 "림" 입니다. 변경된 코드를 비판적 관점에서 전문적으로 검토하여 개선점을 제시합니다.

**PR 요구사항**: {requirements}

**실제 변경된 코드 (diff 분석)**:
{diff_analysis}

다음 지침에 따라 **실제 시니어 전문가 수준의 비판적 피드백**을 작성해주세요:

1. **잠재적 문제점**: 코드 품질, 성능, 보안, 확장성 관점에서 개선이 필요한 부분
2. **설계 원칙 검토**: SOLID, DRY, KISS 등 설계 원칙 관점에서의 개선 방안
3. **베스트 프랙티스**: 해당 언어/프레임워크의 관례나 모범 사례 준수 여부
4. **구체적 개선 제안**: 실제 코드 예시와 함께 명확한 개선 방법 제시

**출력 형식**:
- 문제점과 함께 반드시 구체적인 해결책 제시
- 각 개선사항을 명확한 제목과 함께 구조화
- "🚨 [문제영역]: [구체적 문제점 및 개선방안]" 형태로 작성

예시:
🚨 **기능 완전성**: 라인별 댓글 기능을 완전히 제거했으나, 중요한 보안 이슈나 버그는 여전히 라인별 지적이 필요할 수 있음. 선택적 라인 댓글 옵션 고려 필요
🚨 **설정 관리**: `generate_ai_line_comments()` 함수는 삭제했으나 관련 상수들은 여전히 남아있어 코드 정리 필요
🚨 **에러 처리**: 통합 리뷰 생성 실패 시 fallback 메커니즘 부재. 최소한의 기본 리뷰라도 제공할 수 있는 예외 처리 로직 추가 권장
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
    """실제 diff 내용을 Before/After 비교 형태로 분석하여 AI가 트레이드오프를 분석할 수 있도록 구성"""
    diff_analysis = []

    for file in files[:MAX_FILES_TO_ANALYZE]:  # 설정값 사용
        filename = file.get("filename", "")
        patch = file.get("patch", "")
        additions = file.get("additions", 0)
        deletions = file.get("deletions", 0)
        status = file.get("status", "modified")  # added, removed, modified

        if not patch and status != "added":
            continue

        # 파일 상태별 분석
        if status == "added":
            file_summary = f"""**새 파일 추가**: `{filename}` (+{additions} 라인)

**추가된 주요 내용**:
```
{patch.split('@@')[2] if '@@' in patch else patch[:500]}...
```

**분석 포인트**: 새로운 파일 추가로 인한 프로젝트 구조 변화, 의존성 영향, 네이밍 컨벤션 준수 여부"""

        elif status == "removed":
            file_summary = f"""**파일 삭제**: `{filename}` (-{deletions} 라인)

**삭제 이유 분석 필요**: 해당 파일의 기능이 다른 곳으로 이동했는지, 더 이상 필요없는지 확인 필요"""

        else:  # modified
            # Before/After 코드 비교 분석
            before_lines = []
            after_lines = []
            context_lines = []

            lines = patch.split('\n')
            current_context = ""

            for line in lines:
                if line.startswith('@@'):
                    # 함수/클래스 컨텍스트 추출
                    import re
                    context_match = re.search(r'@@ .* @@(.*)', line)
                    if context_match:
                        current_context = context_match.group(1).strip()
                    continue

                if line.startswith('-') and not line.startswith('---'):
                    code_line = line[1:].strip()
                    # 의미있는 코드 변경만 포함 (빈 줄, 단순 괄호, 주석 제외)
                    if (code_line and
                        not code_line.startswith(('#', '//', '/*', '*')) and
                        len(code_line) > 3 and
                        not code_line in ['{', '}', '(', ')', ';', ',']):
                        before_lines.append(f"  - {code_line}")

                elif line.startswith('+') and not line.startswith('+++'):
                    code_line = line[1:].strip()
                    if (code_line and
                        not code_line.startswith(('#', '//', '/*', '*')) and
                        len(code_line) > 3 and
                        not code_line in ['{', '}', '(', ')', ';', ',']):
                        after_lines.append(f"  + {code_line}")

                elif line.startswith(' ') and len(line.strip()) > 3:
                    # 컨텍스트 라인 (변경되지 않은 주변 코드)
                    context_lines.append(f"    {line[1:].strip()}")

            # Before/After 비교가 의미있는 경우만 포함
            if before_lines or after_lines:
                file_summary = f"""**파일 수정**: `{filename}` (+{additions}/-{deletions})
**컨텍스트**: {current_context if current_context else '전역 범위'}

**🔄 Before vs After 비교**:

**Before (제거된 코드)**:
```
{chr(10).join(before_lines[:MAX_REMOVED_LINES_PER_FILE_DIFF]) if before_lines else '(제거된 코드 없음)'}
```

**After (추가된 코드)**:
```
{chr(10).join(after_lines[:MAX_ADDED_LINES_PER_FILE_DIFF]) if after_lines else '(추가된 코드 없음)'}
```

**주변 컨텍스트**:
```
{chr(10).join(context_lines[:3]) if context_lines else '(컨텍스트 정보 없음)'}
```

**분석 포인트**: 이 변경으로 인한 성능, 가독성, 유지보수성, 확장성 측면의 트레이드오프 분석 필요"""
            else:
                continue

        diff_analysis.append(file_summary)

    return "\n\n" + "="*80 + "\n\n".join(diff_analysis) + "\n\n" + "="*80 if diff_analysis else "분석할 만한 유의미한 코드 변경사항이 없습니다."

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

    # 긍정 리뷰 ("봐")
    positive_review = f"""## ✅ 봐 (긍정적 시각)
{ai_reviews.get('positive', '피드백 생성 중 오류 발생')}"""

    # 중립 리뷰 ("드")
    neutral_review = f"""## ⚖️ 드 (분석적 시각)
{ai_reviews.get('neutral', '피드백 생성 중 오류 발생')}"""

    # 부정 리뷰 ("림")
    critical_review = f"""## 🚨 림 (개선 관점)
{ai_reviews.get('critical', '피드백 생성 중 오류 발생')}"""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

# AI 기반 코드 리뷰 작성 (신규)
async def create_code_review_with_requirements(repo_name, pr_number, files, token, project_info, requirements):
    """AI 완전 위임 기반 코드 리뷰 작성 - 하이브리드 방식 (통합 리뷰 + 선택적 라인 댓글)"""
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 🎯 AI 완전 위임 기반 3명의 리뷰어 피드백 생성
    feedback = await generate_reviewer_feedback_with_ai(project_info, files, repo_name, token, requirements)

    # 🚨 중요한 이슈만 선별적으로 라인 댓글 생성
    critical_line_comments = await generate_critical_line_comments(files, requirements)
    _LOGGER.info(f"생성된 중요 이슈 라인 댓글: {len(critical_line_comments)}개")

    # 라인 댓글 요약 정보
    line_comment_summary = ""
    if critical_line_comments:
        line_comment_summary = f"\n\n> 💡 **중요 이슈 {len(critical_line_comments)}개**를 해당 코드 라인에 직접 댓글로 표시했습니다. 보안, 성능, 품질 문제 중심으로 선별했습니다."
    else:
        line_comment_summary = "\n\n> ✅ **중요한 이슈 없음**: 보안, 성능, 품질 관점에서 즉시 수정이 필요한 문제는 발견되지 않았습니다."

    # 전체 리뷰 본문 (AI 기반) - 통합 리뷰 + 라인 댓글 안내
    review_body = f"""# 🤖 **AI 코드 리뷰 완료**

## 📋 **리뷰 개요**
- **PR 요구사항**: {requirements}
- **변경 규모**: {project_info['changes']['changed_files']}개 파일, +{project_info['changes']['additions']}/-{project_info['changes']['deletions']} 라인{line_comment_summary}

---

## ✅ **봐 (긍정적 관점)**
{feedback['positive']}

---

## ⚖️ **드 (분석적 관점)**
{feedback['neutral']}

---

## 🚨 **림 (개선 관점)**
{feedback['critical']}

---

## 🎯 **리뷰 결론**
변경된 코드에 대한 Before/After 비교 분석과 트레이드오프 검토를 완료했습니다.
중요한 이슈는 해당 라인에 직접 댓글로 표시했으니 확인해주세요! 🚀"""

    # GitHub API 리뷰 데이터 - 하이브리드 방식 (통합 리뷰 + 선택적 라인 댓글)
    review_data = {
        "body": review_body,
        "event": "COMMENT"
    }

    # 중요한 이슈가 있을 때만 라인 댓글 추가
    if critical_line_comments and len(critical_line_comments) > 0:
        review_data["comments"] = critical_line_comments

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=review_data)
            response.raise_for_status()
            _LOGGER.info(f"PR #{pr_number}에 AI 기반 하이브리드 코드 리뷰 작성 완료 (라인 댓글: {len(critical_line_comments)}개)")
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
    """PR 제목, 본문에서 요구사항 추출 - AI 처리를 위한 개선된 버전"""
    pr = payload.get("pull_request", {})

    title = pr.get("title", "").strip()
    # body가 None인 경우를 안전하게 처리
    body = pr.get("body") or ""
    if body:
        body = body.strip()

    # 제목은 필수적으로 포함
    requirements = f"**PR 제목**: {title}\n\n"

    if body:
        # 간단한 마크다운 헤더 기반 내용 추출 시도 (예시)
        # 실제로는 더 정교한 파싱 필요
        important_sections = []
        if "### 주요 변경 사항" in body:
            important_sections.append(body.split("### 주요 변경 사항")[1].split("###")[0].strip())
        if "### 기대 결과" in body:
            important_sections.append(body.split("### 기대 결과")[1].split("###")[0].strip())

        if important_sections:
            requirements += "**PR 본문 (주요 내용)**:\n" + "\n\n".join(important_sections)
        elif len(body) > MAX_PR_BODY_LENGTH_FOR_REQUIREMENTS: # 설정값 사용
            requirements += f"**PR 본문 (요약)**:\n{body[:PR_BODY_SUMMARY_PREFIX_LENGTH]}...\\n...{body[-PR_BODY_SUMMARY_SUFFIX_LENGTH:]}" # 설정값 사용
        else:
            requirements += f"**PR 본문**:\n{body}"
    else:
        requirements += "PR 본문에 내용이 없습니다."

    if not title and not body:
        return "요구사항을 파악할 수 없습니다. PR 제목이나 본문을 확인해주세요."

    return requirements

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

        #  AI 완전 위임 기반 코드 리뷰 작성!
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

async def generate_critical_line_comments(files, requirements):
    """중요한 이슈만 선별하여 라인별 댓글 생성 - 보안, 버그, 성능 문제 중심"""
    if not llm:
        return []

    critical_comments = []

    for file in files[:MAX_FILES_TO_ANALYZE]:
        filename = file.get("filename", "")
        patch = file.get("patch", "")

        if not patch:
            continue

        # 중요한 변경사항만 추출
        critical_changes = []
        lines = patch.split('\n')
        current_line_number = 0

        for line in lines:
            if line.startswith('@@'):
                import re
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_number = int(match.group(1))
                continue

            if line.startswith('+') and not line.startswith('+++'):
                code_line = line[1:].strip()

                # 중요한 이슈가 될 수 있는 패턴들 감지
                critical_patterns = [
                    # 보안 관련
                    ('password', '비밀번호 하드코딩'),
                    ('secret', '시크릿 하드코딩'),
                    ('api_key', 'API 키 하드코딩'),
                    ('eval(', 'eval 사용 위험'),
                    ('exec(', 'exec 사용 위험'),
                    ('shell=True', '쉘 인젝션 위험'),

                    # 성능 관련
                    ('for.*in.*range.*len', '비효율적 반복문'),
                    ('time.sleep', '동기 sleep 사용'),
                    ('requests.get', '비동기 환경에서 동기 HTTP'),

                    # 에러 처리 관련
                    ('except:', '광범위한 예외 처리'),
                    ('pass', '빈 예외 처리'),

                    # 코드 품질
                    ('TODO', '미완성 코드'),
                    ('FIXME', '수정 필요 코드'),
                    ('print(', '디버그 코드 잔존'),
                    ('console.log', '디버그 코드 잔존'),
                ]

                for pattern, issue_type in critical_patterns:
                    if pattern.lower() in code_line.lower():
                        critical_changes.append({
                            'line': current_line_number,
                            'code': code_line,
                            'issue_type': issue_type,
                            'pattern': pattern
                        })
                        break

                current_line_number += 1
            elif line.startswith(' '):
                current_line_number += 1

        # 중요한 이슈에 대해서만 AI 댓글 생성
        for change in critical_changes[:3]:  # 파일당 최대 3개의 중요 이슈만
            try:
                prompt = f"""당신은 시니어 개발자입니다. 다음 코드에서 발견된 중요한 이슈에 대해 구체적인 피드백을 제공해주세요.

**파일**: `{filename}` (라인: {change['line']})
**PR 요구사항**: {requirements}
**감지된 이슈**: {change['issue_type']}

**문제가 될 수 있는 코드**:
```
{change['code']}
```

**분석 지침**:
1. **구체적 문제점**: 이 코드가 왜 문제가 될 수 있는지 명확히 설명
2. **보안/성능/품질 영향**: 실제 운영 환경에서 발생할 수 있는 문제들
3. **구체적 해결방안**: 정확한 코드 예시와 함께 개선 방법 제시

**출력 형식**:
- 80-120자 내외로 핵심만 간결하게
- 문제점과 해결책을 모두 포함
- 실제 코드 예시 제공

예시: "🚨 보안 위험: 하드코딩된 API 키가 노출됩니다. `os.getenv('API_KEY')` 또는 환경변수로 변경하세요."

피드백:"""

                response = await llm.ainvoke([SystemMessage(content=prompt)])
                comment_text = response.content.strip()

                if comment_text and not comment_text.lower().startswith("피드백:"):
                    critical_comments.append({
                        "path": filename,
                        "line": change['line'],
                        "body": f"🚨 **{change['issue_type']}**\n\n{comment_text}"
                    })

            except Exception as e:
                _LOGGER.error(f"중요 이슈 댓글 생성 실패 ({filename} L{change['line']}): {str(e)}")
                critical_comments.append({
                    "path": filename,
                    "line": change['line'],
                    "body": f"🚨 **{change['issue_type']}**: `{change['code'][:50]}...` - 검토 필요"
                })

    _LOGGER.info(f"생성된 중요 이슈 댓글: {len(critical_comments)}개")
    return critical_comments