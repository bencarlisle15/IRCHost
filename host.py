import bcrypt
import hashlib
import json
from uuid import uuid4
from encryption_commands import encrypt_aes
from sql_commands import add_user, get_user_data, get_key, add_session_id, get_user, remove_account, get_session_id, add_message, get_message


def register(request, data, key):
	user = data['user']
	password = data['password']
	salt = bcrypt.gensalt()
	salted = password + salt.decode('utf-8')
	hash_object = hashlib.sha512(bytes(salted, 'utf-8'))
	hashed = hash_object.hexdigest()
	if add_user(user, hashed, salt, key):
		response = encrypt_aes(json.dumps({'status': 'success', 'message': 'You are now registered'}), key)
	else:
		response = encrypt_aes(json.dumps({'status': 'error', 'message': 'That username already exists try another'}), key)
	request.sendall(response)


def login(request, data):
	user = data['user']
	password = data['password']
	user_data = get_user_data(user)
	key = get_key(user)
	if not key:
		print("Key not found1")
		return False
	elif key == True or user_data == True:
		print("Multiple users have been created1")
		exit(1)
	elif not user_data:
		response = encrypt_aes(json.dumps({'status': 'error', 'message': 'Incorrect username or password'}), key)
	else:
		salt = user_data[1]
		salted = password + salt.decode('utf-8')
		hash_object = hashlib.sha512(bytes(salted, 'utf-8'))
		hashed = hash_object.hexdigest()
		if hashed != user_data[0]:
			response = encrypt_aes(json.dumps({'status': 'error', 'message': 'Incorrect username or password'}), key)
		else:
			session_id = str(uuid4())
			if add_session_id(user, session_id):
				response = encrypt_aes(json.dumps({'status': 'success', 'message': 'You are now signed in', 'session_id': session_id}), key)
			else:
				remove_account(user)
				response = encrypt_aes(json.dumps({'status': 'error', 'message': 'You are currently signed in twice, we are deleting your account'}), key)
	request.sendall(response)
	return True


def send_message(request, data):
	user = get_user(data['session_id'])
	key = get_key(user)
	if not key:
		print("Key not found2")
		return False
	elif user == True or key == True:
		print("Multiple users have been created2")
		exit(1)
	elif data['from'] != user or not user:
		response = encrypt_aes(json.dumps({'status': 'error', 'message': 'You are not currently authenticated'}), key)
	else:
		to_key = get_key(data['to'])
		if not key:
			response = encrypt_aes(json.dumps({'status': 'error', 'message': 'Other user not signed in'}), key)
		elif key == True:
			print("Multiple users have been created3")
			exit(1)
		else:
			to_send = encrypt_aes(json.dumps({'status': 'success', 'from': user, 'to': data['to'], 'message': data['message']}), key)
			session_id = get_session_id(data['to'])
			if session_id in [True, False]:
				if session_id:
					remove_account(data['to'])
					add_message(session_id, encrypt_aes(json.dumps({'status': 'error', 'message': 'You are currently signed in twice, we are deleting your account'}), key))
				response = encrypt_aes(json.dumps({'status': 'error', 'message': 'Other user not signed in'}), key)
			else:
				add_message(session_id, to_send)
				response = encrypt_aes(json.dumps({'status': 'success', 'message': 'Message successfully sent'}), key)
	request.sendall(response)
	return True


def request_message(request, data):
	session_id = data['data']
	user = get_user(session_id)
	key = get_key(user)
	if not key:
		print("Key not found5")
		return False
	elif key == True or user == True:
		print("Multiple users have been created5")
		exit(1)
	elif not user:
		response = encrypt_aes(json.dumps({'status': 'error', 'message': 'You are not currently authenticated'}), key)
	else:
		response = get_message(session_id)
		if not response:
			response = encrypt_aes(json.dumps({'status': 'ok', 'message': 'No messages found'}), key)
	request.sendall(response)
