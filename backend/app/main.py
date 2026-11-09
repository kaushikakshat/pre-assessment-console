from fastapi import FastAPI

app = FastAPI(title="Pre-Assessment Platform", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/api/health")
def health():
    return {"status": "ok"}
