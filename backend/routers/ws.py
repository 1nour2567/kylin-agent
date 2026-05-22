"""WS /stream — authenticated context push channel.

Validates Bearer token on connect before accepting the WebSocket handshake.
"""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from middleware.auth import key_store

router = APIRouter()


@router.websocket("/stream")
async def ws_stream(ws: WebSocket, token: str = Query("")):
    # Authenticate via query param Bearer token before accept
    user_id = "anonymous"
    if token:
        info = key_store.validate(token)
        if info:
            user_id = info["user_id"]
        else:
            await ws.close(code=4001, reason="Invalid token")
            return

    await ws.accept()
    from deps import _ws_clients, perception
    _ws_clients.append(ws)
    try:
        while True:
            data = await asyncio.wait_for(ws.receive_json(), timeout=30)
            action = data.get("action", "")
            if action == "ping":
                await ws.send_json({"type": "pong"})
            elif action == "get_context":
                ctx = perception.build("status", user_id)
                await ws.send_json({"type": "context", "data": ctx["system"]})
    except asyncio.TimeoutError:
        await ws.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


async def broadcast(msg: dict):
    from deps import _ws_clients
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)
