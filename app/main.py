"""
Recon Automation Platform - Main FastAPI Application

This is the entry point for the web application.
Run with: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.database import init_db
from app.config import settings
from app.api.routes import projects, scans, results, websocket as ws_routes
from app.core.executor import executor


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown events."""
    # Startup
    logger.info("Starting Recon Automation Platform...")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Check available tools
    tools = await executor.check_all_tools()
    available = [t for t, v in tools.items() if v]
    logger.info(f"Available tools: {len(available)}/{len(tools)}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")


# Create FastAPI application
app = FastAPI(
    title="Recon Automation Platform",
    description="Automated bug bounty reconnaissance management and monitoring",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(results.router)
app.include_router(ws_routes.router)

# Get frontend directory
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main frontend page."""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>Frontend not found. Please check installation.</h1>")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/api/tools")
async def get_tool_status():
    """Get status of all security tools."""
    tools = await executor.check_all_tools()
    return {
        "tools": tools,
        "available_count": sum(1 for v in tools.values() if v),
        "total_count": len(tools),
    }


# Mount static files if frontend directory exists
if FRONTEND_DIR.exists():
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=FRONTEND_DIR / "css"), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=FRONTEND_DIR / "js"), name="js")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
