#!/usr/bin/env python

import imaplib
import email
import configparser
import os
import logging
import sys
import re
import processor
import imap_reader
import argparse
from rss2email import feeds as _feeds
from rss2email import error as _error


def get_config(path):
	config = configparser.ConfigParser()
	config.read([path])
	return config


if __name__ == '__main__':

	parser = argparse.ArgumentParser(
		description="Convert RSS to email and manage users subscriptions and feeds through email messages."
	)
	parser.add_argument('config', metavar='CONFIG', help="The configuration file")
	parser.add_argument('-r', '--run-all', dest='run_all', action='store_true', help="Fetch and send all feeds of all users")
	args = parser.parse_args()

	if not os.path.isfile(args.config):
		sys.stderr.write("[ERROR] Configuration file '" + args.config + "' doesn't exist\n")
		exit(2)
	

	# get configuration
	config = get_config(args.config)

	# set the log level and log format accordingly
	log_level = config.get('log', 'level').upper()
	log_format = config.get('log', 'format')
	if log_level == 'DEBUG':
		logging.basicConfig(level=logging.DEBUG,format=log_format)
	elif log_level == 'INFO':
		logging.basicConfig(level=logging.INFO,format=log_format)
	elif log_level == 'WARNING':
		logging.basicConfig(level=logging.WARNING,format=log_format)
	elif log_level == 'ERROR':
		logging.basicConfig(level=logging.ERROR,format=log_format)
	else:
		sys.stderr.write("[ERROR] Invalid log level '" + log_level + "'\n")
		exit(2)

	# fetch and send
	if args.run_all:

		# for each user's dir
		data_dir = config.get('rss2email', 'data_dir')
		logging.debug("From data dir: '%s'", data_dir)
		for d in os.listdir(data_dir):
			d_path = os.path.join(data_dir, d)
			if os.path.isdir(d_path) and '@' in d:
				logging.debug("\tUser: %s", d)
				data_file = os.path.join(d_path, config.get('rss2email', 'data_filename'))
				config_file = os.path.join(d_path, config.get('rss2email', 'configuration_filename'))
				# run each feed (fetch then send)
				feeds = _feeds.Feeds(datafile=data_file, configfiles=[config_file])
				feeds.load(lock=True)
				if feeds:
					try:
						for feed in feeds:
							if feed.active:
								try:
									logging.debug("\t\tFeed: %s", feed.name)
									feed.run(send=True)
								except _error.RSS2EmailError as e:
									e.log()
					finally:
						logging.debug("\t\tSaving...")
						feeds.save()
				else:
					logging.debug("\t\tNo feed")
	
	# management messages
	else:

		# get connection parameters
		hostname =   config.get('imap', 'hostname')
		port 	   = config.get('imap', 'port')
		username   = config.get('account', 'username')
		password   = config.get('account', 'password')
		inbox_name = config.get('mailbox', 'inbox')

		# open connection
		imap_conn = imap_reader.open_connection(hostname, port, username, password)
		if not imap_conn:
			logging.error("Failed to login to '%s:%s' with user '%s'", hostname, port, username)
			sys.exit(1)

		try:
			# select mailbox
			rv, data = imap_conn.select(inbox_name)
			if rv != 'OK':
				logging.error("Failed to selecting INBOX '%s'", inbox_name)
				imap_conn.close()
				sys.exit(1)

			# set config for processor module
			processor.set_config(config)

			# open smtp connection
			processor.init_smtp()

			# load translations and set locale
			locales_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'locales')
			processor.load_translations(locales_dir)
			locale = config.get('service', 'lang')
			processor.set_locale(locale)

			# process messages
			logging.debug("Processing mailbox ...")
			for num, msg in imap_reader.get_messages(imap_conn):
				if processor.process_message(msg):
					imap_reader.mark_msg_as_read(imap_conn, num)
				else:
					imap_reader.mark_msg_as_not_read(imap_conn, num)
				#imap_reader.mark_msg_as_not_read(imap_conn, num)

			# closing mailbox
			logging.debug("Closing IMAP mailbox ...")
			imap_conn.close()

			# close smtp connection
			processor.close_smtp()
			

		finally:
			logging.debug("Logging out IMAP")
			imap_conn.logout()

