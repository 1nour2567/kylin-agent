"""Persistent SSH tunnel: VM:8443 -> api.deepseek.com:443"""
import os
import sys
import socket
import threading
import time

import paramiko

VM_HOST = os.environ.get("KYLIN_VM_HOST")
VM_USER = os.environ.get("KYLIN_VM_USER")
VM_PASS = os.environ.get("KYLIN_VM_PASS")
TUNNEL_PORT = int(os.environ.get("TUNNEL_PORT", "8443"))
TARGET_HOST = os.environ.get("TUNNEL_TARGET_HOST", "api.deepseek.com")
TARGET_PORT = int(os.environ.get("TUNNEL_TARGET_PORT", "443"))

for var, name in [(VM_HOST, "KYLIN_VM_HOST"), (VM_USER, "KYLIN_VM_USER"), (VM_PASS, "KYLIN_VM_PASS")]:
    if not var:
        print(f"Error: {name} environment variable must be set", file=sys.stderr)
        sys.exit(1)


def make_handler():
    def handler(channel, src_addr, dest_addr):
        print(f"[tunnel] connection from {src_addr}")
        try:
            sock = socket.socket()
            sock.settimeout(10)
            sock.connect((TARGET_HOST, TARGET_PORT))
            print(f"[tunnel] connected to {TARGET_HOST}:{TARGET_PORT}")
        except Exception as e:
            print(f"[tunnel] upstream connect failed: {e}")
            channel.close()
            return

        def forward(src, dst, direction):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    src.close()
                    dst.close()
                except Exception:
                    pass

        t1 = threading.Thread(target=forward, args=(channel, sock, "vm->ds"), daemon=True)
        t2 = threading.Thread(target=forward, args=(sock, channel, "ds->vm"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    return handler


def main():
    print(f"Connecting to {VM_HOST}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(VM_HOST, username=VM_USER, password=VM_PASS, timeout=10)
    transport = client.get_transport()

    transport.request_port_forward("", TUNNEL_PORT, make_handler())
    print(f"Tunnel active: VM:{TUNNEL_PORT} -> {TARGET_HOST}:{TARGET_PORT}")

    # Test immediately
    stdin, stdout, stderr = client.exec_command(
        f'curl -sk --connect-timeout 10 '
        f'--connect-to "{TARGET_HOST}:{TARGET_PORT}:127.0.0.1:{TUNNEL_PORT}" '
        f'https://{TARGET_HOST}/v1/models 2>&1 | head -5'
    )
    time.sleep(12)
    result = stdout.read().decode()
    err = stderr.read().decode()
    print(f"API test: {result[:500] if result else '(empty)'}")
    if err:
        print(f"Stderr: {err[:300]}")

    print("Tunnel running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("Stopping...")
        transport.cancel_port_forward("", TUNNEL_PORT)
        client.close()


if __name__ == "__main__":
    main()
