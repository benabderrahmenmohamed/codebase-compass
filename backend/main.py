"""Backend entry point: app creation, CORS, router mounting."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import analyses, auth, notifications, projects, users

app = FastAPI(
    title="Codebase Compass",
    description="Understand an unfamiliar codebase: security, readability, "
    "maintainability, performance, best practices.",
    version="0.2.0",
)

# Browsers block calls between different origins (:5173 -> :8000) until the
# backend explicitly allows the frontend's origin.
origins = ["http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(analyses.router)
app.include_router(projects.router)
app.include_router(users.router)
app.include_router(notifications.router)


@app.get("/", tags=["Health"])
def health_check():
    return {"status": "ok", "message": "Backend is running"}
