import json
import socketserver
import time

from encryption_commands import decrypt_rsa, decrypt_aes
from sql_commands import get_key
from host import register, login, send_message, request_message


class MyTCPHandler(socketserver.BaseRequestHandler):
	"""
	The request handler class for our server.

	It is instantiated once per connection to the server, and must
	override the handle() method to implement communication to the
	client.
	"""

	def handle(self):
		print(self.request)
		# request is the TCP socket connected to the client
		main_data = self.request.recv(4096).strip()
		loaded_json = json.loads(main_data)
		data = loaded_json['data']
		try:
			encrypted_key = loaded_json['key']
			key = decrypt_rsa(encrypted_key)
		except KeyError:
			user = decrypt_rsa(loaded_json['user']).decode('utf-8')
			key = get_key(user)
			if not key:
				print("Key not found4")
				return False
			elif key == True:
				print("Multiple users have been created4")
				exit(1)

		d = decrypt_aes(data, key)
		decrypted_json = d.decode('utf-8').strip("".join(map(chr, range(1, 33))))
		json_text = json.loads(decrypted_json)
		if json_text['message_type'] == 'register':
			register(self.request, json_text, key)
		elif json_text['message_type'] == 'login':
			login(self.request, json_text)
		elif json_text['message_type'] == 'send_message':
			send_message(self.request, json_text)
		elif json_text['message_type'] == 'ping':
			request_message(self.request, json_text)


if __name__ == "__main__":
	HOST, PORT = "172.16.68.71", 4000

	# Create the server, binding to localhost on port 9999
	while True:
		try:
			server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
			print("Started server")
			break
		except OSError:
			time.sleep(0.1)
	# Activate the server; this will keep running until you
	# interrupt the program with Ctrl-C
	server.serve_forever()
