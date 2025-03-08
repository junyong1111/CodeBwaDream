from fastapi import APIRouter, Request


router = APIRouter()

# 서버 상태 체크
@router.get("/webhook/health")
async def health_check():
    return {"message": "It's Working On webhook Service!"}

@router.post("/github-webhook")
async def github_webhook(request: Request):
    payload = await request.json()
    print(payload)  # GitHub 이벤트 데이터 출력 (테스트용)
    return {"status": "Webhook received!"}