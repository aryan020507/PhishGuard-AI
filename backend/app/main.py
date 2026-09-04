"""
Main FastAPI Application for PhishGuard-AI.
Mounts API endpoints, lifespan events, clean exception handlers, and static frontend assets.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.app.config import APP_NAME, APP_VERSION, APP_DESCRIPTION, FRONTEND_DIR
from backend.app.api.endpoints import router as api_router
from backend.app.services.model_loader import ModelManager
from backend.app.services.history_service import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: Initialize DB and load ML models on startup."""
    logger.info("Initializing PhishGuard-AI application lifecycle...")
    # Initialize SQLite database
    init_db()
    # Load ML models and preprocessing pipelines once on startup
    ModelManager.get_instance().load_all_models()
    logger.info("Application startup sequence completed successfully.")
    yield
    logger.info("PhishGuard-AI application shutting down.")


# Create FastAPI application
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=APP_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clean Error Handlers (Never leak stack traces)
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle 422 Unprocessable Entity with clean JSON error formatting."""
    error_messages = []
    for err in exc.errors():
        field = " -> ".join(str(loc) for loc in err.get("loc", []))
        msg = err.get("msg", "Invalid input")
        error_messages.append(f"{field}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "Validation Error",
            "detail": "; ".join(error_messages),
            "status_code": 422
        }
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with clean JSON responses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP Error",
            "detail": str(exc.detail),
            "status_code": exc.status_code
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Handle unhandled server exceptions without leaking internal stack traces."""
    logger.error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected server error occurred. Please verify your input and try again.",
            "status_code": 500
        }
    )


# Include API Endpoints Router
app.include_router(api_router)


# Mount static frontend directory
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    async def serve_index():
        """Serve the frontend SPA entry point."""
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return JSONResponse({"status": "Frontend not found"}, status_code=404)
