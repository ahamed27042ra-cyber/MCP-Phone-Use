import base64
import hmac
import os

from starlette.responses import JSONResponse, PlainTextResponse

import server


def _authorized(request) -> bool:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return False
    try:
        raw = base64.b64decode(header[6:].strip()).decode("utf-8")
        username, password = raw.split(":", 1)
    except Exception:
        return False
    return hmac.compare_digest(username, os.environ.get("DEVICE_AGENT_USERNAME", "")) and hmac.compare_digest(
        password, os.environ.get("DEVICE_AGENT_PASSWORD", "")
    )


@server.mcp.custom_route("/enrollment-code", methods=["GET"])
async def enrollment_code(request):
    if not _authorized(request):
        return PlainTextResponse(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="MCP Phone Use"'},
        )
    code = server.device_registry.generate_enrollment_code()
    return JSONResponse({"enrollment_code": code, "expires_in": 600})


if __name__ == "__main__":
    startup_code = server.device_registry.generate_enrollment_code()
    server.logger.info("STARTUP_ENROLLMENT_CODE=%s", startup_code)
    server.logger.info("Starting MCP Phone Use relay wrapper")
    server.mcp.run(transport="streamable-http")
