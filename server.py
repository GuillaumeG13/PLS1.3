from tls_socket import *

def callback(socket):
	data = socket.receive()
	print(data.decode())

# socket = SocketTLS(ip="127.0.0.1", port=1799, server=True, workers=5, callback=callback)
# socket.initialize_connection()
socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, callback=callback)
socket.initialize_connection()
socket.update("One two one two\n")
send = socket.send()
print("Client send : " + send)
