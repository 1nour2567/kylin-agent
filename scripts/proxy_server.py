"""Minimal HTTP/HTTPS forward proxy for Kylin VM to reach internet.
Run on Windows host. VM connects to http://<windows_ip>:8888 as proxy.
"""
import socket
import threading
import select

HOST = '0.0.0.0'
PORT = 8888


def handle_client(client_sock, addr):
    try:
        data = client_sock.recv(8192)
        if not data:
            client_sock.close()
            return

        first_line = data.split(b'\r\n')[0].decode('utf-8', errors='ignore')
        print(f'REQ: {first_line[:80]}')

        # Parse CONNECT method (HTTPS) or GET/POST (HTTP)
        if first_line.startswith('CONNECT'):
            # HTTPS tunnel
            target = first_line.split()[1]  # host:port
            host, port = target.rsplit(':', 1) if ':' in target else (target, 80)
            port = int(port)
            remote = socket.socket()
            remote.settimeout(15)
            try:
                remote.connect((host, port))
                client_sock.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            except Exception as e:
                client_sock.sendall(f'HTTP/1.1 502 Bad Gateway\r\n\r\n{str(e)}'.encode())
                client_sock.close()
                return

            # Bidirectional relay
            sockets = [client_sock, remote]
            try:
                for _ in range(300):  # ~30 seconds at 0.1s poll
                    r, _, _ = select.select(sockets, [], [], 0.1)
                    for s in r:
                        d = s.recv(4096)
                        if not d:
                            return
                        if s is client_sock:
                            remote.sendall(d)
                        else:
                            client_sock.sendall(d)
            except Exception:
                pass
            finally:
                remote.close()
        else:
            # Plain HTTP - extract host and forward
            import re
            match = re.search(rb'Host: ([^\r\n]+)', data)
            if not match:
                client_sock.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header')
                client_sock.close()
                return
            host = match.group(1).decode()
            if ':' not in host:
                host = f'{host}:80'
            h, p = host.rsplit(':', 1)
            p = int(p)

            remote = socket.socket()
            remote.settimeout(15)
            try:
                remote.connect((h, p))
                remote.sendall(data)
            except Exception as e:
                client_sock.sendall(f'HTTP/1.1 502 Bad Gateway\r\n\r\n{str(e)}'.encode())
                client_sock.close()
                return

            # Relay response
            try:
                while True:
                    d = remote.recv(4096)
                    if not d:
                        break
                    client_sock.sendall(d)
            except Exception:
                pass
            finally:
                remote.close()

    except Exception as e:
        print(f'ERR: {e}')
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    print(f'Proxy listening on {HOST}:{PORT}')
    while True:
        try:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
    server.close()


if __name__ == '__main__':
    main()
