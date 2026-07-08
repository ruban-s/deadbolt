# 2. A framework-agnostic core via a normalized request/response

Date: 2026-07-08

## Status

Accepted

## Context

The library must mount on any Python web framework (FastAPI, Starlette, Litestar, Flask, Django,
Quart, Sanic, aiohttp). Unlike JavaScript, Python has no universal request/response object shared
across frameworks, and frameworks split across ASGI (async) and WSGI (sync). We must avoid coupling
the core to any one framework and avoid duplicating logic per framework.

## Decision

The core speaks a library-owned `AuthRequest` / `AuthResponse` and exposes a single
`async def handle(request) -> response`. Each framework gets a thin adapter that translates native ↔
normalized and applies cookies through the framework's own cookie API. WSGI frameworks bridge to the
async core through one long-lived `anyio.BlockingPortal`, not per-call `async_to_sync`. Endpoints are
also plain callables, giving a server-side direct API for free. Persistence stays behind an adapter
Protocol so the core never owns event-loop or greenlet concerns.

## Consequences

Adding a framework is ~30 lines and no core change. The cost is maintaining our own request/response
types and a portal for the sync bridge. Cookies must be carried as structured data because frameworks
lock response headers at different times; this is an explicit, tested concern rather than an
afterthought.
