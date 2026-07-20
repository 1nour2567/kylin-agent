"""WS /stream — authenticated context push channel with per-user isolation."""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from middleware.auth import key_store

router = APIRouter()


@router.websocket("/stream")
async def ws_stream(ws: WebSocket):
    # No token in URL — use post-connect auth message (#11)
    await ws.accept()
    user_id = "anonymous"
    role = "viewer"
    authenticated = False

    from deps import _ws_clients, perception

    try:
        # Wait for first auth message (#11, #20: 10s timeout)
        first_msg = await asyncio.wait_for(ws.receive_json(), timeout=10)
        if first_msg.get("action") == "auth":
            token = first_msg.get("token", "")
            if token:
                info = key_store.validate(token)
                if info:
                    user_id = info["user_id"]
                    role = info.get("role", "viewer")
                    authenticated = True
                    await ws.send_json({"type": "auth_ok", "role": role})
                else:
                    await ws.send_json({"type": "auth_failed"})
            else:
                await ws.send_json({"type": "auth_failed", "reason": "no token"})
    except asyncio.TimeoutError:
        await ws.send_json({"type": "auth_timeout"})
        await ws.close(code=4001)
        return

    # Register with user context for per-user isolation (#10)
    client_info = {"ws": ws, "user_id": user_id, "role": role}
    _ws_clients.append(client_info)

    try:
        await ws.send_json({"type": "heartbeat"})
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_json(), timeout=25)
                action = data.get("action", "")
                if action == "ping":
                    await ws.send_json({"type": "pong"})
                elif action == "get_context":
                    ctx = perception.build("status", user_id, role=role)
                    await ws.send_json({"type": "context", "data": ctx["system"]})
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive (#20)
                try:
                    await ws.send_json({"type": "heartbeat"})
                except Exception:
                    break
                continue  # Keep looping
    except WebSocketDisconnect:
        pass
    finally:
        for c in list(_ws_clients):
            if c.get("ws") == ws:
                _ws_clients.remove(c)
                break


async def broadcast(msg: dict, actor_user_id: str = "", actor_role: str = ""):
    """Send msg to connected clients, filtered by permission (#10)."""
    from deps import _ws_clients
    dead = []
    for client in _ws_clients:
        ws_conn = client["ws"]
        # Admin sees everything; others only see their own events
        if actor_role != "admin" and client["user_id"] != actor_user_id:
            continue
        try:
            await ws_conn.send_json(msg)
        except Exception:
            dead.append(client)
    for d in dead:
        if d in _ws_clients:
            _ws_clients.remove(d)
