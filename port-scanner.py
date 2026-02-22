import socket

for port in range (1, 5000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex(("192.168.1.15", port))
    if result == 0:
        print("Port " + str(port) + " is open")
    else:
        print("Port " + str(port)+ "is closed")
    sock.close()