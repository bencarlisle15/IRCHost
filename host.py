import bcrypt
import hashlib
import json
from uuid import uuid4
from encryption_commands import encrypt_aes
from sql_commands import add_user, get_user_data, get_key, add_session_id, get_user, remove_account, get_session_id, add_message, get_message, update_session, remove_session, AppearanceCount


def register(request, data, key):
	try:
		user = data['user']
		password = data['password']
		salt = bcrypt.gensalt()
		salted = password + salt.decode('utf-8')
		hash_object = hashlib.sha512(bytes(salted, 'utf-8'))
		hashed = hash_object.hexdigest()
		if add_user(user, hashed, salt, key):
			response = encrypt_aes(json.dumps({'status': 201, 'message': 'You are now registered'}), key)
		else:
			response = encrypt_aes(json.dumps({'status': 409, 'message': 'That username already exists try another'}), key)
	except KeyError:
		response = bytes(json.dumps({'status': 400, 'message': 'Invalid format'}), 'utf-8')
	request.sendall(response)


def login(request, data):
	try:
		user = data['user']
		password = data['password']
		user_data = get_user_data(user)
		key = get_key(user)
		if key == AppearanceCount.Empty:
			response = bytes(json.dumps({'status': 401, 'message': 'Incorrect username or password'}), 'utf-8')
		elif key == AppearanceCount.Multiple:
			remove_account(user)
			response = bytes(json.dumps({'status': 423, 'message': 'You are currently signed in twice, we are deleting your account'}), 'utf-8')
		elif user_data == AppearanceCount.Empty:
			response = encrypt_aes(json.dumps({'status': 401, 'message': 'Incorrect username or password'}), key)
		elif user_data == AppearanceCount.Multiple:
			remove_account(user)
			response = encrypt_aes(json.dumps({'status': 423, 'message': 'You are currently signed in twice, we are deleting your account'}), key)
		else:
			salt = user_data[1]
			salted = password + salt.decode('utf-8')
			hash_object = hashlib.sha512(bytes(salted, 'utf-8'))
			hashed = hash_object.hexdigest()
			if hashed != user_data[0]:
				response = encrypt_aes(json.dumps({'status': 401, 'message': 'Incorrect username or password'}), key)
			else:
				session_id = str(uuid4())
				if add_session_id(user, session_id):
					response = encrypt_aes(json.dumps({'status': 202, 'message': 'You are now signed in', 'session_id': session_id}), key)
				else:
					remove_account(user)
					response = encrypt_aes(json.dumps({'status': 423, 'message': 'You are currently signed in twice, we are deleting your account'}), key)
	except KeyError:
		response = bytes(json.dumps({'status': 400, 'message': 'Invalid format'}), 'utf-8')
	request.sendall(response)


def send_message(request, data):
	try:
		session_id = data['session_id']
		user = get_user(session_id)
		if user == AppearanceCount.Multiple:
			remove_session(session_id)
			response = bytes(json.dumps({'status': 502, 'message': 'An internal service error has occurred'}), 'utf-8')
		elif user == AppearanceCount.Empty:
			response = bytes(json.dumps({'status': 403, 'message': 'You are not currently authenticated'}), 'utf-8')
		else:
			key = get_key(user)
			if key == AppearanceCount.Empty:
				response = bytes(json.dumps({'status': 403, 'message': 'You are not currently authenticated'}), 'utf-8')
			elif key == AppearanceCount.Multiple:
				remove_account(user)
				response = bytes(json.dumps({'status': 423, 'message': 'You are currently signed in twice, we are deleting your account'}), 'utf-8')
			else:
				recipient = data['to']
				recipient_key = get_key(recipient)
				recipient_session_id = get_session_id(recipient)
				if recipient_key == AppearanceCount.Empty or recipient_key == AppearanceCount.Empty:
					response = encrypt_aes(json.dumps({'status': 410, 'message': 'Other user not signed in'}), key)
				elif recipient_key == AppearanceCount.Multiple or recipient_session_id == AppearanceCount.Multiple:
					remove_account(recipient)
					response = encrypt_aes(json.dumps({'status': 410, 'message': 'Other user not signed in'}), key)
				else:
					to_send = encrypt_aes(json.dumps({'status': 200, 'from': user, 'to': data['to'], 'is_file': data['is_file'], 'message': data['message']}), recipient_key)
					add_message(recipient_session_id, to_send)
					response = encrypt_aes(json.dumps({'status': 200, 'message': 'Message successfully sent'}), key)
	except KeyError:
		response = bytes(json.dumps({'status': 400, 'message': 'Invalid format'}), 'utf-8')
	request.sendall(response)
	

def request_message(request, data):
	try:
		session_id = data['session_id']
		user = get_user(session_id)
		if user == AppearanceCount.Multiple:
			remove_session(session_id)
			response = bytes(json.dumps({'status': 502, 'message': 'An internal service error has occurred'}), 'utf-8')
		elif user == AppearanceCount.Empty:
			response = bytes(json.dumps({'status': 403, 'message': 'You are not currently authenticated'}), 'utf-8')
		else:
			key = get_key(user)
			if key == AppearanceCount.Empty:
				response = bytes(json.dumps({'status': 403, 'message': 'You are not currently authenticated'}), 'utf-8')
			elif key == AppearanceCount.Multiple:
				remove_account(user)
				response = bytes(json.dumps({'status': 423, 'message': 'You are currently signed in twice, we are deleting your account'}), 'utf-8')
			else:
				update_session(session_id)
				response = get_message(session_id)
				if not response:
					response = encrypt_aes(json.dumps({'status': 100, 'message': 'No messages found'}), key)
	except KeyError:
		response = bytes(json.dumps({'status': 400, 'message': 'Invalid format'}), 'utf-8')
	request.sendall(response)
