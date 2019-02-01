from threading import Thread
import time
from datetime import datetime
from sql_commands import get_all_messages, get_all_sessions, remove_message, remove_session

MAX_CHECK_IN_TIME = 5


def sweep_messages():
	messages = get_all_messages()
	for message in messages:
		message_time = datetime.strptime(message[1], '%Y-%m-%d %H:%M:%S')
		if (datetime.utcnow() - message_time).total_seconds() > MAX_CHECK_IN_TIME:
			print("Collecting Message: " + str(message[0]))
			remove_message(message[0])


def sweep_sessions():
	sessions = get_all_sessions()
	for session in sessions:
		session_time = datetime.strptime(session[1], '%Y-%m-%d %H:%M:%S')
		if (datetime.utcnow() - session_time).total_seconds() > MAX_CHECK_IN_TIME:
			print("Collecting Session: " + str(session[0]))
			remove_session(session[0])


class Collector(Thread):
	
	def run(self):
		while True:
			sweep_messages()
			sweep_sessions()
			time.sleep(1)
