import logging
import json

from fastapi import HTTPException, Request

from src.app.helper import code_agent as agent_helper
from src.config.settings import (
    GITHUB_WEBHOOK_SECRET,
)

_LOGGER = logging.getLogger(__name__)

async def get_code_review_agent_service(request: Request):
    # 웹훅 서명 검증
    try:
        _LOGGER.info("웹훅 서명 검증 시작")
        if GITHUB_WEBHOOK_SECRET:
            signature = request.headers.get("X-Hub-Signature-256")
            raw_body = await request.body()
            if not agent_helper.verify_webhook_signature(raw_body, signature, GITHUB_WEBHOOK_SECRET):
                _LOGGER.error("잘못된 웹훅 서명")
                raise HTTPException(status_code=401, detail="잘못된 웹훅 서명")

        # GitHub 이벤트 타입 확인
        _LOGGER.info("GitHub 이벤트 타입 확인 시작")
        event_type = request.headers.get("X-GitHub-Event")
        #event_type => pull_request

        # 페이로드 파싱 및 로깅
        payload = await request.json()

        # 웹훅 데이터 로깅 추가
        _LOGGER.info(f"GitHub 이벤트 수신: {event_type}")
        _LOGGER.info(f"웹훅 페이로드: {json.dumps(payload, indent=2, ensure_ascii=False)}")

        # 풀 리퀘스트 이벤트 처리
        _LOGGER.info("풀 리퀘스트 이벤트 처리 시작")
        action = payload.get("action")

        # 코드 리뷰가 필요한 액션들
        code_review_actions = ["opened", "synchronize", "reopened"]
        # 알림만 보내는 액션들
        notification_actions = ["assigned", "review_requested", "ready_for_review"]

        if event_type == "pull_request":
            if action in code_review_actions:
                _LOGGER.info(f"코드 리뷰 실행: {action} 액션")
                await agent_helper.handle_pull_request(payload)
            elif action in notification_actions:
                _LOGGER.info(f"알림 처리: {action} 액션")
                await agent_helper.handle_pr_notification(payload)
            else:
                _LOGGER.info(f"처리하지 않는 액션: {action}")

        return {"status": "받음", "event_type": event_type, "action": action}

    except Exception as e:
        _LOGGER.error(f"웹훅 처리 중 오류 발생: {str(e)}", exc_info=True)
        raise HTTPException(status_code=401, detail=str(e))
