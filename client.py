from tls_socket import *

def callback(tls_socket):
	return "callback client"

socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, callback=callback)
socket.initialize_connection()
socket.update("One two one two\n")
send = socket.send()
print("Client send : " + send)
