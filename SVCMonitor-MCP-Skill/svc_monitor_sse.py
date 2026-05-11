#!/usr/bin/env python3
"""
SVC Monitor MCP - SSE Transport 启动器
用于通过 HTTP SSE 方式暴露 MCP 接口（适合远程调用场景）
"""

import asyncio
import argparse
from svc_monitor_mcp import app
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn


sse = SseServerTransport("/messages/")


async def handle_sse(request):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await app.run(
            streams[0], streams[1], app.create_initialization_options()
        )


async def handle_messages(request):
    await sse.handle_post_message(request.scope, request.receive, request._send)


async def health(request):
    return JSONResponse({"status": "ok", "server": "svc-monitor"})


starlette_app = Starlette(
    routes=[
        Route("/health", health),
        Route("/sse", handle_sse),
        Mount("/messages/", routes=[Route("/{path:path}", handle_messages, methods=["POST"])]),
    ],
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3001)
    args = parser.parse_args()

    print(f"🚀 SVC Monitor MCP (SSE) listening on http://{args.host}:{args.port}")
    print(f"   SSE endpoint: http://{args.host}:{args.port}/sse")
    uvicorn.run(starlette_app, host=args.host, port=args.port)
