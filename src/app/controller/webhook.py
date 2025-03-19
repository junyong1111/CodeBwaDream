from fastapi import APIRouter, Request

from src.app.service import code_agent

router = APIRouter()

# 서버 상태 체크
@router.get("/webhook/health")
async def health_check():
    return {"message": "It's Working On webhook Service!"}

@router.post("/github-webhook")
async def github_webhook(request: Request):
    return code_agent.get_code_review_agent_service(request)