"""
自定义鉴权模块 - 支持 URL Token 和 Bearer Token
"""
from typing import Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """
    Token 鉴权中间件
    支持两种方式传递 Token：
    1. URL 参数: ?token=xxx
    2. HTTP Header: Authorization: Bearer xxx
    """

    def __init__(self, app, token: str):
        super().__init__(app)
        self.token = token

    async def dispatch(self, request: Request, call_next):
        # 检查 Token
        # 1. 从 URL 参数获取
        query_params = dict(request.query_params)
        url_token = query_params.get("token")

        # 2. 从 Authorization Header 获取 (Bearer Token)
        auth_header = request.headers.get("Authorization", "")
        header_token = None
        if auth_header.startswith("Bearer "):
            header_token = auth_header[7:]

        # 验证 Token（URL 或 Header 任一有效即可）
        if url_token != self.token and header_token != self.token:
            return JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "Unauthorized: Invalid or missing token"
                    },
                    "id": None
                }
            )

        response = await call_next(request)
        return response
