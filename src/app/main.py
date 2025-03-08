from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/github-webhook")
async def github_webhook(request: Request):
    payload = await request.json()
    print(payload)  # GitHub 이벤트 데이터 출력 (테스트용)
    return {"status": "Webhook received!"}