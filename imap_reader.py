#!/usr/bin/env python

import imaplib
import email
import configparser
import os
import logging
import sys
import re
import processor
import rss2email


def get_config(path):
	config = configparser.ConfigParser()
	config.read([path])
	return config


def open_connection(hostname, port, username, password):
	# Connecting
	logging.debug("Openning IMAP SSL connection to '%s:%s'", hostname, port)
	connection = imaplib.IMAP4_SSL(host=hostname, port=port)

	# Login to our account
	logging.debug("Login IMAP with user '%s'", username)
	connection.login(username, password)
	return connection


def get_messages(conn):
	typ, data = conn.search(None,'(UNSEEN)')
	for num in data[0].split():
		rv, data = conn.fetch(num,'(RFC822)')
		if rv != 'OK':
			logging.error("Failed to get message '%s'", num)
			return
		msg = email.message_from_bytes(data[0][1])
		yield (num, msg)


def mark_msg_as_read(conn, num):
	typ, data = conn.store(num,'+FLAGS','\\Seen')
	logging.debug('\t\tFlaged as READ')


def mark_msg_as_not_read(conn, num):
	typ, data = conn.store(num,'-FLAGS','\\Seen')
	logging.debug('\t\tFlaged as NOT READ')


