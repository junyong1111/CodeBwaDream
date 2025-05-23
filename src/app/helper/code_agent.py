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

# 3명의 리뷰어 페르소나 정의
def generate_reviewer_feedback(project_info, files):
    """3명의 리뷰어(긍정, 중립, 부정)가 피드백을 생성"""
    language = project_info["language"]
    framework = project_info["framework"]
    changes = project_info["changes"]
    branch = project_info["branch"]

    # 파일 분석
    file_analysis = analyze_changed_files(files)

    # 긍정적 리뷰어 (Alex - 동기부여형)
    positive_review = f"""## 🌟 긍정적 리뷰 (Alex)

안녕하세요! 멋진 작업이네요! 👏

**코드 분석:**
- **언어/프레임워크**: {language}/{framework} - 훌륭한 선택입니다!
- **브랜치**: `{branch}` - 기능 개발 브랜치 네이밍이 깔끔하네요
- **변경사항**: {changes['changed_files']}개 파일, +{changes['additions']}/-{changes['deletions']} 라인

**좋은 점들:**
✅ {framework} 프레임워크를 활용한 체계적인 개발
✅ 적절한 분량의 변경사항 ({changes['additions']} 라인 추가)
✅ 기능별 브랜치 관리가 잘 되어 있음

{file_analysis['positive']}

계속해서 이런 좋은 코드를 작성해주세요! 🚀"""

    # 중립적 리뷰어 (Morgan - 분석형)
    neutral_review = f"""## ⚖️ 중립적 리뷰 (Morgan)

코드 변경사항에 대한 객관적 분석입니다.

**기술 스택 분석:**
- 주언어: {language}
- 프레임워크: {framework}
- 브랜치: {branch}

**변경사항 메트릭스:**
- 수정된 파일: {changes['changed_files']}개
- 추가된 라인: {changes['additions']}
- 삭제된 라인: {changes['deletions']}
- 커밋 수: {changes['commits']}

**코드 품질 관찰:**
{file_analysis['neutral']}

**제안사항:**
- 코드 리뷰 후 테스트 케이스 추가 검토
- 문서화 업데이트 확인
- 성능 영향도 체크"""

    # 부정적 리뷰어 (Jordan - 엄격형)
    critical_review = f"""## 🔍 비판적 리뷰 (Jordan)

코드 품질 향상을 위한 엄격한 검토입니다.

**우려사항:**
- {language}/{framework} 스택에서 {changes['changed_files']}개 파일 동시 수정은 변경 범위가 클 수 있음
- {changes['additions']}줄 추가 대비 {changes['deletions']}줄 삭제 - 코드 증가량 검토 필요

{file_analysis['critical']}

**개선 요구사항:**
⚠️ 단위 테스트 커버리지 확인 필수
⚠️ 에러 핸들링 로직 점검
⚠️ 보안 취약점 스캔 권장
⚠️ 성능 최적화 여부 검토

**코드 품질 기준:**
- 복잡도 분석 필요
- 주석 및 문서화 개선
- 코딩 컨벤션 준수 확인

더 엄격한 코드 리뷰가 필요합니다."""

    return {
        "positive": positive_review,
        "neutral": neutral_review,
        "critical": critical_review
    }

def analyze_changed_files(files):
    """변경된 파일들을 분석하여 각 리뷰어별 코멘트 생성"""
    if not files:
        return {
            "positive": "✅ 파일 변경사항이 체계적으로 관리되고 있습니다.",
            "neutral": "📁 파일 변경사항을 분석하기 위해 세부 정보가 필요합니다.",
            "critical": "⚠️ 변경된 파일 정보를 확인할 수 없어 코드 품질 평가가 제한됩니다."
        }

    python_files = [f for f in files if f.get("filename", "").endswith(".py")]
    config_files = [f for f in files if f.get("filename", "").endswith((".json", ".yaml", ".yml", ".toml"))]

    positive = "✅ " + (f"Python 파일 {len(python_files)}개의 체계적인 수정" if python_files else "설정 파일들의 적절한 관리")
    neutral = f"📊 총 {len(files)}개 파일 변경 - Python 파일 {len(python_files)}개, 설정 파일 {len(config_files)}개"
    critical = "⚠️ " + (f"{len(files)}개 파일 동시 수정으로 인한 리스크 검토 필요" if len(files) > 3 else "변경 범위 적절함")

    return {
        "positive": positive,
        "neutral": neutral,
        "critical": critical
    }

# 향상된 코드 리뷰 작성
async def create_code_review(repo_name, pr_number, files, token, project_info):
    url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # 3명의 리뷰어 피드백 생성
    feedback = generate_reviewer_feedback(project_info, files)

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