import os
import sys

# Ensure all candidate project root locations are in sys.path
this_file = os.path.abspath(__file__)
this_dir = os.path.dirname(this_file)
parent_dir = os.path.dirname(this_dir)
cwd = os.getcwd()

candidate_paths = [cwd, parent_dir, this_dir, "/var/task"]
for p in candidate_paths:
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

try:
    from backend.app.main import app
except Exception as e:
    import traceback
    err_tb = traceback.format_exc()
    print("FATAL ERROR loading FastAPI app in api/index.py:", err_tb, file=sys.stderr)
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    app = FastAPI(title="PhishGuard-AI Diagnostic Mode")

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "HEAD", "OPTIONS"])
    async def diagnostic_error(full_path: str):
        return JSONResponse(
            status_code=500,
            content={
                "error": "Serverless Startup Failure",
                "detail": str(e),
                "traceback": err_tb,
                "sys_path": sys.path,
                "cwd": os.getcwd(),
                "file": __file__,
                "dir_contents": os.listdir(os.getcwd()) if os.path.exists(os.getcwd()) else []
            }
        )
