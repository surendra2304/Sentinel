"""Deliberately Vulnerable Localhost Lab Application for Sentinel E2E Verification.

Features:
- Missing security headers (HSTS, CSP, X-Frame-Options)
- Insecure cookie flags (Missing Secure, HttpOnly, SameSite)
- Directory listing exposure (/static/backups/)
- Permissive CORS reflector (Access-Control-Allow-Origin: *)
- Weak JWT configuration (/api/jwt/debug)
- Exposed backup file (/backup/database.sql.bak)
- Outdated component fingerprint (Server: Apache/2.4.49 vulnerable header)
- High-impact gated action requiring Level-3 Operator Authorization (/api/admin/flush-database)
"""

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

lab_app = FastAPI(title="Sentinel Vulnerable Lab Target")


@lab_app.get("/")
async def root(response: Response):
    # Deliberately missing CSP, HSTS, X-Content-Type-Options
    response.set_cookie(key="session_token", value="insecure_raw_session_12345", httponly=False, secure=False)
    response.headers["Server"] = "Apache/2.4.49 (Unix) OpenSSL/1.1.1d"
    return HTMLResponse("<html><body><h1>Sentinel Target Web Server</h1><a href='/static/backups/'>Backups</a></body></html>")


@lab_app.get("/static/backups/")
async def directory_listing():
    # Deliberate directory listing vulnerability
    return HTMLResponse("<html><body><h1>Index of /static/backups/</h1><ul><li><a href='database.sql.bak'>database.sql.bak</a></li></ul></body></html>")


@lab_app.get("/backup/database.sql.bak")
async def exposed_backup():
    return PlainTextResponse("-- DATABASE DUMP --\nCREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(64));\nINSERT INTO users VALUES (1, 'admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');\n")


@lab_app.get("/api/cors-reflect")
async def permissive_cors(request: Request, response: Response):
    origin = request.headers.get("origin", "*")
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"status": "cors_reflected", "origin": origin}


@lab_app.get("/api/jwt/debug")
async def weak_jwt():
    # Weak none-algorithm JWT token
    return {"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJ1c2VyIn0."}


@lab_app.post("/api/admin/flush-database")
async def high_impact_gated_action(request: Request):
    auth = request.headers.get("X-Sentinel-Authorization")
    if auth != "OPERATOR_LEVEL_3_APPROVED":
        return JSONResponse(status_code=403, content={"error": "Level 3 Operator Human Approval Required."})
    return {"status": "success", "action": "database_flushed", "verified": True}
