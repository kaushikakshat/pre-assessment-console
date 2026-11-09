import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.startup import validate_env
from app.api import admin, admin_users, assessments, auth, catalog, dashboard, findings, jobs, reports, retest, signin


@asynccontextmanager
async def lifespan(_):
    validate_env()
    yield


app = FastAPI(title="Pre-Assessment Platform", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

CSRF_EXEMPT = {"/api/auth/login", "/api/auth/mfa"}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    if (path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS") and path not in CSRF_EXEMPT):
        cookie, header = request.cookies.get("pa_csrf", ""), request.headers.get("x-csrf-token", "")
        if not cookie or not hmac.compare_digest(cookie.encode(), header.encode()):
            resp = JSONResponse({"detail": "Your session expired. Reload the page and try again."}, 403)
        else:
            resp = await call_next(request)
    else:
        resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    if path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    fields = {str(e["loc"][-1]): "Enter a valid value." for e in exc.errors()}
    return JSONResponse({"detail": {"fields": fields}}, 422)


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(auth.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(admin_users.router, prefix="/api")
app.include_router(assessments.router, prefix="/api")
app.include_router(catalog.router, prefix="/api")
app.include_router(jobs.router, prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(retest.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(signin.router, prefix="/api")
