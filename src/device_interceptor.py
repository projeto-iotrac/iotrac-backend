import socket

def send_udp(ip: str, port: int, message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ip, port))

def send_tcp(ip: str, port: int, message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    sock.sendall(message.encode())
    sock.close()