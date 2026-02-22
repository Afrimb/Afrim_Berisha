import socket
from Crypto.Cipher import AES
import base64

KEY = b'12345678901234567890123456789012'
IV = b'1234567890123456'

def encrypt_message(msg):
    while len(msg) % 16 != 0:
        msg += ' '
    
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(msg.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5000))  

message = input("Enter message: ")
encrypted_msg = encrypt_message(message)
print(f"Encrypted Message sent by client: {encrypted_msg}")

client_socket.sendall(encrypted_msg.encode())
client_socket.close()