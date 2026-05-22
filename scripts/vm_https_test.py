import socket, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = socket.socket()
s.settimeout(10)
try:
    s.connect(("127.0.0.1", 8443))
    ss = ctx.wrap_socket(s, server_hostname="api.deepseek.com")
    ss.sendall(b"GET /v1/models HTTP/1.1\r\nHost: api.deepseek.com\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
    data = ss.recv(4096)
    print(data.decode()[:500])
except Exception as e:
    print(f"Error: {e}")
