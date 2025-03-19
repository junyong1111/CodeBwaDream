import logging

from fastapi import HTTPException, Request

from src.app import helper
from src.config.settings import (
    GITHUB_APP_ID,
    GITHUB_APP_PRIVATE_KEY,
    GITHUB_WEBHOOK_SECRET,
)

_LOGGER = logging.getLogger(__name__)

async def get_code_review_agent_service(request: Request):
    # 웹훅 서명 검증
    try:
        _LOGGER.info("웹훅 서명 검증 시작")
        if GITHUB_WEBHOOK_SECRET:
            signature = request.headers.get("X-Hub-Signature-256")
            if not helper.code_agent.verify_webhook_signature(await request.body(), signature, GITHUB_WEBHOOK_SECRET):
                _LOGGER.error("잘못된 웹훅 서명")
                raise HTTPException(status_code=401, detail="잘못된 웹훅 서명")

        # GitHub 이벤트 타입 확인
        _LOGGER.info("GitHub 이벤트 타입 확인 시작")
        event_type = request.headers.get("X-GitHub-Event")
        payload = await request.json()
        _LOGGER.info(f"GitHub 이벤트 수신: {event_type}")

        # 풀 리퀘스트 이벤트 처리
        _LOGGER.info("풀 리퀘스트 이벤트 처리 시작")
        if event_type == "pull_request" and payload.get("action") in ["opened", "synchronize"]:
            await helper.code_agent.handle_pull_request(payload)

        return {"status": "받음", "event_type": event_type}

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
