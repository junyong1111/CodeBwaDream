# CodeBwaDream

> **코드 리뷰는 AI에게 맡기고, 커피 한 잔 하러 가세요! ☕️**

CodeBwaDream은 GitHub Pull Request에 올라온 코드를 자동으로 분석하고, AI가 코드 리뷰 코멘트를 남겨주는 FastAPI 기반 서비스입니다.  
GitHub App과 연동하여, 코드 리뷰의 번거로움을 덜어주고 개발자의 생산성을 높여줍니다.

---

## 주요 특징

- **AI 기반 코드 리뷰:**  
  PR에 올라온 코드를 자동으로 분석해, 개선점이나 이슈를 코멘트로 남깁니다.
- **GitHub App 연동:**  
  내 계정이 아닌 봇 계정으로 리뷰가 작성되어 부담 없이 코드 품질을 높일 수 있습니다.
- **FastAPI 서버:**  
  GitHub Webhook 이벤트를 빠르게 받아 처리합니다.
- **확장성:**  
  LangGraph 등 다양한 AI 분석 도구와 연동 가능.


## 사용 방법

1. [GitHub Apps](https://github.com/settings/apps)에서 CodeBwaDream 앱을 생성하고,  
   필요한 권한(Pull requests: Read & Write, Contents: Read-only)과 이벤트(Pull request, Pull request review, Pull request review comment)를 설정하세요.
2. 앱을 저장소에 설치합니다.
3. PR이 생성되면, CodeBwaDream 서버가 Webhook을 받아 자동으로 코드 리뷰 코멘트를 남깁니다.
