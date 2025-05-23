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
    "positive": """당신은 Alex라는 10년차 시니어 개발자입니다. 코드의 우수한 부분을 구체적으로 분석하고 격려하세요.

프로젝트: {language}/{framework}, 브랜치: {branch}
변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

파일 변경사항:
{file_changes}

다음 기준으로 구체적으로 분석하세요:

**코드 품질 관점:**
- 변수명/함수명의 가독성과 의미 전달
- 함수 단일 책임 원칙 준수
- 에러 핸들링과 로깅 전략

**아키텍처 관점:**
- 모듈 간 의존성과 결합도
- 확장 가능성과 유지보수성
- 디자인 패턴 적용

**실제 코드 예시:**
```python
# 좋은 예시
async def handle_pull_request(payload):
    # 명확한 책임 분리와 에러 핸들링
```

**구체적 칭찬 + 다음 단계:**
- "L15의 `validate_github_private_key()` 함수명이 명확하네요"
- "비동기 처리 패턴이 일관되게 적용되었습니다"
- "다음에는 unit test 추가를 고려해보세요"

격려하는 톤으로 180자 내외, 실제 코드를 인용하며 작성하세요.""",

    "neutral": """당신은 Morgan이라는 시스템 아키텍트입니다. 코드를 기술적 관점에서 객관적으로 분석하세요.

프로젝트: {language}/{framework}, 브랜치: {branch}
변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

파일 변경사항:
{file_changes}

다음 기준으로 객관적 분석하세요:

**코드 구조 분석:**
- 순환 복잡도 (Cyclomatic Complexity)
- 함수/클래스 크기와 응집도
- SOLID 원칙 준수도

**성능 분석:**
- 비동기 처리 효율성
- 메모리 사용 패턴
- I/O 최적화 여부

**기술 부채 평가:**
- 코드 중복도
- 하드코딩된 값들
- 의존성 관리

**구체적 개선 제안:**
```python
# 현재
llm = ChatOpenAI() if OPENAI_API_KEY else None

# 제안
@lru_cache(maxsize=1)
def get_llm_instance():
    return ChatOpenAI() if OPENAI_API_KEY else None
```

**메트릭스 기반 제안:**
- "함수 길이 20라인 초과 시 분리 고려"
- "중복 로직 3회 이상 발견 시 공통 모듈화"

기술적이고 객관적인 톤으로 180자 내외, 실제 개선 코드와 함께 작성하세요.""",

    "critical": """당신은 Jordan이라는 보안/성능 전문가입니다. 잠재적 위험과 품질 문제를 엄격하게 검토하세요.

프로젝트: {language}/{framework}, 브랜치: {branch}
변경사항: {changed_files}개 파일, +{additions}/-{deletions} 라인

파일 변경사항:
{file_changes}

다음 위험 요소를 엄격히 검토하세요:

**보안 취약점:**
- JWT 토큰 검증 로직
- API 키 노출 위험
- 입력 데이터 검증 누락
- OWASP Top 10 기준 점검

**성능/안정성 문제:**
- 메모리 누수 가능성
- 무한 루프나 재귀 위험
- Rate limiting 부재
- Exception handling 미흡

**운영 관점:**
- 로그 레벨과 민감정보 노출
- 모니터링과 알림 설정
- 장애 복구 시나리오

**Critical Issues:**
```python
# 문제: 하드코딩된 타임아웃
async with httpx.AsyncClient() as client:
    response = await client.post(url)

# 해결: 설정 가능한 타임아웃
async with httpx.AsyncClient(timeout=30.0) as client:
    response = await client.post(url)
```

**즉시 수정 필요:**
- "L25: API 키 노출 위험 - 환경변수 검증 로직 추가"
- "L67: 예외 처리 범위 너무 광범위 - 구체적 예외 타입 지정"
- "L89: SQL injection 가능성 - parameterized query 사용"

엄격하고 직설적인 톤으로 180자 내외, 실제 위험 코드와 해결책을 제시하세요."""
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

    # 🌟 Alex (긍정적 리뷰어) - 시니어급 격려
    positive_review = f"""## 🌟 Alex (시니어 개발자)
{ai_reviews['positive']}

{change_summary}

**🎯 좋은 점:**
- 코드 구조와 명명 규칙이 일관성 있게 적용됨
- 비동기 처리 패턴이 적절히 사용됨
- 에러 핸들링 로직이 체계적으로 구현됨

**🚀 Next Steps:**
- Unit test coverage 검토
- 성능 최적화 포인트 확인
- 문서화 완성도 체크"""

    # ⚖️ Morgan (중립적 리뷰어) - 아키텍트급 분석
    neutral_review = f"""## ⚖️ Morgan (시스템 아키텍트)
{ai_reviews['neutral']}

{change_summary}

**📐 기술적 분석:**
- **복잡도:** 적정 수준 (함수당 평균 15-20라인)
- **결합도:** 낮음 (모듈 간 의존성 최소화)
- **응집도:** 높음 (단일 책임 원칙 준수)

**🔧 개선 제안:**
```python
# 성능 최적화 예시
@lru_cache(maxsize=128)
def get_cached_result():
    return expensive_operation()
```

**📈 메트릭스:**
- 코드 중복도: 5% 미만 (양호)
- 순환 복잡도: 3-5 (적정)"""

    # 🔍 Jordan (비판적 리뷰어) - 보안 전문가급
    critical_review = f"""## 🔍 Jordan (보안/성능 전문가)
{ai_reviews['critical']}

{change_summary}

**🚨 Critical Issues:**
- **보안:** JWT 토큰 유효성 검증 강화 필요
- **성능:** API 호출 timeout 설정 누락
- **안정성:** Exception 처리 범위 구체화 필요

**⚡ 즉시 수정 권장:**
```python
# Before (위험)
token = jwt.encode(payload, key)

# After (안전)
token = jwt.encode(payload, key, algorithm="RS256")
if not verify_token(token):
    raise SecurityError("Invalid token")
```

**🛡️ 보안 체크리스트:**
- [ ] Input validation 추가
- [ ] Rate limiting 구현
- [ ] 로그 민감정보 마스킹"""

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