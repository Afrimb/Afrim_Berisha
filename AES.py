import socket
from Crypto.Cipher import AES
import base64

KEY = b'12345678901234567890123456789012'
IV = b'1234567890123456'

def decrypt_message(enc_msg):
    encrypted_data = base64.b64decode(enc_msg)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted.decode('utf-8').rstrip(' ')

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('localhost', 5000))
server_socket.listen(1)
print("Server listening on port 5000...")

try:
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    data = conn.recv(1024)
    print(f"Encrypted data received: {data.decode()}")
    
    decrypted_text = decrypt_message(data.decode())
    print(f"Decrypted message: {decrypted_text}")
    
    conn.close()
    
except KeyboardInterrupt:
    print("\nServer stopped by user")
    
finally:
    server_socket.close()
    print("Server closed")