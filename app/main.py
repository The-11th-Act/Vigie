from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1 import assets, vulnerabilities, scans, dashboard, auth

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Risk-Based Vulnerability Management (RBVM) Platform",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Auth"])
app.include_router(dashboard.router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["Dashboard"])
app.include_router(assets.router, prefix=f"{settings.API_V1_STR}/assets", tags=["Assets"])
app.include_router(vulnerabilities.router, prefix=f"{settings.API_V1_STR}/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["Scans"])


@app.get("/")
def read_root():
    return {"status": "online", "project": settings.PROJECT_NAME, "docs": "/docs"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}