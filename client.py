from tls_socket import *

def callback(tls_socket):
	return "callback client"

socket = SocketTLS(ip="127.0.0.1", port=1799, server=False, callback=callback)
socket.initialize_connection()

client_hello = "16030100a5010000a10303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000020cca8cca9c02fc030c02bc02cc013c009c014c00a009c009d002f0035c012000a010000580000001800160000136578616d706c652e756c666865696d2e6e6574000500050100000000000a000a0008001d001700180019000b00020100000d0012001004010403050105030601060302010203ff0100010000120000"
socket.update(client_hello)
send = socket.send()
print("Saying hello")
while True:
	data = socket.receive()
	message = data.decode()
	print("CLIENT: RECEIVED: " + message)
