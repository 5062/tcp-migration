import socket
from datetime import datetime


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('10.0.0.2', 22222))
        s.listen(1)
        print('Server2 bind TCP on 22222...')
        client_sock, addr = s.accept()
        print(f'accepted {addr}')
        try:
            while True:
                data = client_sock.recv(1024)
                now = datetime.now().strftime("%H:%M:%S")
                if data:
                    print(f"[{now}] from {addr[0]}: {data.decode('utf-8')}")
                else:
                    break
                client_sock.send(b'Hello, %s! This is server2' % addr[0].encode('utf-8'))
        except KeyboardInterrupt or Exception:
            s.shutdown(socket.SHUT_RDWR)


if __name__ == '__main__':
    start_server()
