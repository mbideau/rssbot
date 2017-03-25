#!/usr/bin/env python

import re
import logging
import email
import email.header
import datetime
import configparser
import smtp_sender
from os import makedirs
from os.path import join, isfile, isdir
import shutil
from rss2email import feeds as _feeds
from bs4 import BeautifulSoup
import i18n

REGEX_EMAIL_WITH_NAME = re.compile('^ *"?[^"]+"? *<(?P<email>[^>]+)> *$')

SMTP_CONNECTION = None
CONFIG = None


def get_feeds(email):
	d_path = rss2email_get_data_dir_from_email(email)
	data_file = join(d_path, get_config().get('rss2email', 'data_filename'))
	config_file = join(d_path, get_config().get('rss2email', 'configuration_filename'))
	return _feeds.Feeds(datafile=data_file, configfiles=[config_file])


def get_config():
	global CONFIG
	return CONFIG


def set_config(config):
	global CONFIG
	CONFIG = config


def set_locale(locale):
	logging.debug("Service will operate with language: %s (fallback: %s)", locale, 'en')
	i18n.set('locale', locale)
	i18n.set('fallback', 'en')


def load_translations(path):
	logging.debug("Loading translations from: '%s'", path)
	i18n.load_path.append(path)


def process_message(msg):
	# from
	from_who = str(email.header.make_header(email.header.decode_header(msg['From'])))
	email_with_name = REGEX_EMAIL_WITH_NAME.match(from_who)
	if email_with_name:
		from_who = email_with_name.group('email').strip().lower()
	# to
	to_who = str(email.header.make_header(email.header.decode_header(msg['To'])))
	# date
	msg_date = msg['Date']
	date_tuple = email.utils.parsedate_tz(msg['Date'])
	if date_tuple:
		local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
		msg_date = local_date.strftime("%a, %d %b %Y %H:%M:%S")
	# subject
	subject = str(email.header.make_header(email.header.decode_header(msg['Subject'])))
	# body
	body = msg['Body']
	feed = extract_feed_url_from_body(msg)
	logging.info('< [%s] %s %s %s', msg_date, from_who, subject, ('(' + feed + ')' if feed else ''))
	return process_rss2email(from_who, subject.strip().lower(), feed)


def extract_feed_url_from_body(msg):
	url = None
	html = []
	for part in msg.walk():
		# multipart/* are just containers
		if part.get_content_maintype() == 'multipart':
			continue
		#if not part.is_multipart() and part.get_content_type() == 'text/plain':
		if part.get_content_type() == 'text/plain':
			charset = part.get_content_charset()
			lines = part.get_payload(decode=True).decode(charset).strip().split('\n')
			url = get_feed_from_content(lines)
			logging.debug("\t\t\tBody: %d lines (%s) -> feed '%s'", len(lines), charset, url)
			if url:
				break
		elif part.get_content_type() == 'text/html':
			charset = part.get_content_charset()
			lines = part.get_payload(decode=True).decode(charset).strip().split('\n')
			html.extend(lines)
		else:
			logging.debug("\t\tBody skiped: %s (multipart: %s)", part.get_content_type(), part.is_multipart())
	if not url and html:
		url = get_feed_from_content(html, True)
	return url


def get_feed_from_content(content, html=False):
	feed = None
	lines = content
	if isinstance(content, str):
		lines = content.strip().split('\n')
	elif not isinstance(content, list):
		raise TypeError("Parameter 'content' must be a string or a list but found '" + str(type(content)) + "'")
	if html:
		soup = BeautifulSoup('\n'.join(lines), 'html.parser')
		links = soup.find_all('a')
		for l in links:
			if re.match('^https?://[^         ]+$', l, re.IGNORECASE):
				feed = l
				break

	if not html or not feed:
		for l in lines:
			match = re.search('(https?://[^ 	<>]+)', l, re.IGNORECASE)
			if match:
				found = match.group(1)
				feed = found
				if isinstance(found, list):
					feed = found[0]
				break
			
	return feed


def get_feed_name_from_url(url):
	return re.sub(r'^https?://([^/]+)/?.*$', '\\1', url)


def get_actions():
	return [
		i18n.t('rssbot.subscribe'),
		i18n.t('rssbot.unsubscribe'),
		i18n.t('rssbot.add'),
		i18n.t('rssbot.delete'),
		i18n.t('rssbot.list')
	]


def process_rss2email(email, action, url):
	subject = get_config().get('message', 'subject_prefix') + " Re: " + action.title()

	if not re.match('^[ 	]*(' + '|'.join(get_actions()) + ')[ 	]*$', action, re.IGNORECASE):
		logging.info("\t\tInvalid action '%s'. Skipping.", action)
		logging.debug("\t\tAllowed actions in lang '%s': %s", i18n.get('locale'), ', '.join(get_actions()))
		return True

	has_subscription = rss2email_has_subscriptions(email)
	if not has_subscription and action != i18n.t('rssbot.subscribe'):
		response = i18n.t('rssbot.error_no_subscription',
			email=email, service=get_config().get('service', 'name'), subscribe=i18n.t('rssbot.subscribe')
		)
		send_mail(email, subject, response)
		logging.info("> %s", response)
		return True

	if i18n.t('rssbot.subscribe') == action:
		if has_subscription:
			response = i18n.t('rssbot.error_already_subscribed',
				email=email, service=get_config().get('service', 'name')
			)
			send_mail(email, subject, response)
			logging.info("> %s", response)
		else:
			output = rss2email_new_subscription(email)
			send_mail(email, subject, output)
			logging.info("> %s", output)

	elif i18n.t('rssbot.unsubscribe') == action:
		output = rss2email_remove_subscription(email)
		send_mail(email, subject, output)
		logging.info("> %s", output)

	elif i18n.t('rssbot.add') == action:
		if not url:
			response = i18n.t('rssbot.error_no_feed_found')
			send_mail(email, subject, response)
			logging.info("> %s", response)
		elif rss2email_get_feed_index(email, url) is not None:
			response = i18n.t('rssbot.error_existing_feed', url=url)
			send_mail(email, subject, response)
			logging.info("> %s", response)
		else:
			output = rss2email_add_feed(email, url)
			send_mail(email, subject, output)
			logging.info("> %s", output)

	elif i18n.t('rssbot.delete') == action:
		if not url:
			response = i18n.t('rssbot.error_no_feed_found')
			send_mail(email, subject, response)
			logging.info("> %s", response)
		else:
			feed_index = rss2email_get_feed_index(email, url)
			if not feed_index:
				response = i18n.t('rssbot.error_no_existing_feed', url=url)
				send_mail(email, subject, response)
				logging.info("> %s", response)
			else:
				output = rss2email_remove_feed(email, feed_index)
				send_mail(email, subject, output)
				logging.info("> %s", output)

	elif i18n.t('rssbot.list') == action:
		output = rss2email_list_feeds(email)
		send_mail(email, subject, output)
		logging.info("> (list of feeds)")
	else:
		logging.info("\tInvalid action '%s'. Skipping.", action)
	return True


def check_smtp():
	global SMTP_CONNECTION
	if not SMTP_CONNECTION:
		raise RuntimeError("You must init an SMTP connection with init_smtp() before processing messages")


def init_smtp():
	global SMTP_CONNECTION
	if not SMTP_CONNECTION:
		hostname = get_config().get('smtp', 'hostname')
		port 	 = get_config().get('smtp', 'port')
		username = get_config().get('account', 'username')
		password = get_config().get('account', 'password')
		try:
			SMTP_CONNECTION = smtp_sender.open_connection(hostname, port, username, password)
		except smtplib.SMTPException:
			logging.error("Failed to connect to SMTP server '%s:%s' with user '%s'", hostname, port, username)
			return False

def close_smtp():
	global SMTP_CONNECTION
	smtp_sender.close_connection(SMTP_CONNECTION)


def send_mail(to_addrs, subject, text, html=False):
	global SMTP_CONNECTION
	check_smtp()
	from_bot = get_config().get('message', 'from')
	msg = smtp_sender.build_text_message(from_bot, to_addrs, subject, text)
	smtp_sender.send_message(SMTP_CONNECTION, msg)


# fake to debug
def send_mail_debug(to_addrs, subject, text):
	logging.debug("Message to send:\n-- %s\n%s", subject, text)


def sanitize_email(email):
	return email.replace('/', '').replace(';', '').replace('"', '').replace("'", '').replace(' ', '')


def rss2email_get_data_dir_from_email(email):
	return join(get_config().get('rss2email', 'data_dir'), sanitize_email(email))


def rss2email_has_subscriptions(email):
	d_path = rss2email_get_data_dir_from_email(email)
	return isdir(d_path) \
	and isfile(join(d_path, get_config().get('rss2email', 'configuration_filename'))) \
	and isfile(join(d_path, get_config().get('rss2email', 'data_filename')))


def rss2email_new_subscription(email):
	logging.debug("\t\tNew subscription for '%s'", email)
	feeds = get_feeds(email)
	feeds.config['DEFAULT']['to'] = email
	feeds.config['DEFAULT']['from'] = get_config().get('message', 'from')
	for k, v in get_config()['DEFAULT'].items():
		feeds.config['DEFAULT'][k] = v
	feeds.save()
	return i18n.t('rssbot.action_new_subscription', email=email)


def rss2email_remove_subscription(email):
	d_path = rss2email_get_data_dir_from_email(email)
	if isdir(d_path):
		shutil.rmtree(d_path)
	return i18n.t('rssbot.action_unsubscribed', email=email)


def rss2email_add_feed(email, url):
	name = get_feed_name_from_url(url)
	logging.debug("\t\tAdding feed '%s' (%s) for '%s'", name, url, email)
	feeds = get_feeds(email)
	feeds.load(lock=True)
	feed = feeds.new_feed(name=name, url=url, to=email)
	feeds.save()
	return i18n.t('rssbot.action_feed_added', url=url)


def rss2email_delete_feed(email, index):
	logging.debug("\t\tDeleting feed '%d' for '%s'", index, email)
	feeds = get_feeds(email)
	feeds.load(lock=True)
	feed = feeds.index(index)
	feeds.remove(feed)
	feeds.save()
	return i18n.t('rssbot.action_feed_deleted', url=feed.url)


def rss2email_list_feeds(email):
	logging.debug("\t\tListing feeds for '%s'", email)
	output = []
	feeds = get_feeds(email)
	feeds.load(lock=False)
	for i,feed in enumerate(feeds):
		if feed.active:
			active_char = '*'
		else:
			active_char = ' '
		output.append('{}: [{}] {} ({})'.format(i, active_char, feed.name, feed.url))
	return '\n'.join(output)
	

def rss2email_get_feed_index(email, url):
	feeds = get_feeds(email)
	feeds.load(lock=False)
	for i, feed in enumerate(feeds):
		if feed.url == url:
			return i
	return None

