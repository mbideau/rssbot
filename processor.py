#!/usr/bin/env python

import re
import logging
import email
import email.header
import datetime
import configparser
import smtp_sender
import smtplib
from os import makedirs
from os.path import join, isfile, isdir
import shutil
from rss2email import feed as _feed
from rss2email import feeds as _feeds
from bs4 import BeautifulSoup
import i18n

# BEGIN -- import for function 'check_for_feed_errors'
# copy pasted from rss2email/feed.py
import socket as _socket
_SOCKET_ERRORS = []
for e in ['error', 'herror', 'gaierror']:
	if hasattr(_socket, e):
		_SOCKET_ERRORS.append(getattr(_socket, e))
del e  # cleanup namespace
_SOCKET_ERRORS = tuple(_SOCKET_ERRORS)
import xml.sax as _sax
import feedparser as _feedparser
_feedparser.PREFERRED_XML_PARSERS = []
# END -- import for function 'check_for_feed_errors'


REGEX_EMAIL_WITH_NAME = re.compile('^ *"?[^"]+"? *<(?P<email>[^>]+)> *$')

SMTP_CONNECTION = None
CONFIG = None


def handle_error(exception, msg, result):
	logging.error("Catched an exception (program have aborted): %s", exception)
	email = None

	try:
		msg_date, email, subject, action, feed = parse_message(msg)
		response = i18n.t('rssbot.error_exception',
			error=type(exception).__name__,
			message=subject + (' (' + feed + ')' if feed else ''),
			admin=get_config().get('service', 'admin')
		)
		subject = get_config().get('message', 'subject_prefix') + " Re: " + action.title()

	except Exception as inner_exception:
		logging.error("Catched an inner exception: %s", inner_exception)
		try:
			email = get_email_sender(msg)
			subject = get_config().get('message', 'subject_prefix') + " Error"
			response = i18n.t('rssbot.error_exception_fallback',
							  admin=get_config().get('service', 'admin'),
							  message=str(msg))
		except Exception as inner_inner_exception:
			logging.error("Catched an inner inner exception: %s", inner_inner_exception)

	if email and subject and response:
		try:
			send_mail(email, subject, response)
		except Exception as inner_exception:
			logging.error("Catched an inner exception: %s", inner_exception)
	else:
		logging.error("Cannot send email back to user. Details: email='%s', subject='%s', response='%s'",
					  email, subject, response)


def get_feeds(email):
	d_path = rss2email_get_data_dir_from_email(email)
	data_file = join(d_path, get_config().get('rss2email', 'data_filename'))
	config_file = join(d_path, get_config().get('rss2email', 'configuration_filename'))
	logging.debug("Loading feeds for '%s' (data:'%s', config:'%s')", email, data_file, config_file)
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


def get_email_sender(msg):
	from_who = str(email.header.make_header(email.header.decode_header(msg['From'])))
	email_with_name = REGEX_EMAIL_WITH_NAME.match(from_who)
	if email_with_name:
		from_who = email_with_name.group('email').strip().lower()
	return from_who


def parse_message(msg):
	# from
	from_who = get_email_sender(msg)
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
	action = subject.strip().lower()
	return msg_date, from_who, subject, action, feed


def process_message(msg):
	msg_date, from_who, subject, action, feed = parse_message(msg)
	logging.info('< #%4s %10s [%25s] %40s %s %s', num.decode(), action, msg_date, from_who, subject, ('(' + feed + ')' if feed else ''))
	return process_rss2email(from_who, action, feed)


# a near copy-paste from rss2email/feed.py
# instead of logging notices, warnings and errors, it returns them
def check_for_feed_errors(parsed):
	notices = []
	warnings = []
	errors = []

	status = getattr(parsed, 'status', 200)
	if status not in [200, 301, 302, 304, 307]:
		errors.append("HTTP status is not okay (status=%s)" % status)

	http_headers = parsed.get('headers', {})
	if not http_headers:
		warnings.append('could not get HTTP headers')
	else:
		if 'html' in http_headers.get('content-type', 'rss'):
			warnings.append('looks like HTML')
		if http_headers.get('content-length', '1') == '0':
			warnings.append('empty page')

	version = parsed.get('version', None)
	if not version:
		notices.append('unrecognized version')

	exc = parsed.get('bozo_exception', None)
	if isinstance(exc, _socket.timeout):
		errors.append('timed out')
	elif isinstance(exc, OSError):
		errors.append(str(exc))
	elif isinstance(exc, _SOCKET_ERRORS):
		errors.append(str(exc))
	elif isinstance(exc, _feedparser.zlib.error):
		errors.append('broken compression')
	elif isinstance(exc, (IOError, AttributeError)):
		errors.append(str(exc))
	elif isinstance(exc, KeyboardInterrupt):
		raise exc
	elif isinstance(exc, _sax.SAXParseException):
		errors.append('sax parsing error: {}'.format(exc))
	elif (parsed.bozo and
		  isinstance(exc, _feedparser.CharacterEncodingOverride)):
		warnings.append(
			'incorrectly declared encoding: {}'.format(exc))
	elif (parsed.bozo and isinstance(exc, _feedparser.NonXMLContentType)):
		warnings.append('non XML Content-Type: {}'.format(exc))
	elif parsed.bozo or exc:
		if exc is None:
			exc = "can't process"
		errors.append('processing error: {}'.format(exc))

	if (status in [200, 302] and
		not parsed.entries and
		not version):
		errors.append('processing error')

	return notices, warnings, errors


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
			if charset is None:
				logging.warning("\t\t\tBody(text): charset is None -> feed '%s'", url)
			else:
				payload = part.get_payload(decode=True)
				if payload is None:
					logging.warning("\t\t\tBody(text): payload is None -> feed '%s'", url)
				else:
					lines = payload.decode(charset).strip().split('\n')
					url = get_feed_from_content(lines)
					logging.debug("\t\t\tBody(text): %d lines (%s) -> feed '%s'", len(lines), charset, url)
					if url:
						break
		elif part.get_content_type() == 'text/html':
			charset = part.get_content_charset()
			if charset is None:
				logging.warning("\t\t\tBody(html): charset is None -> feed '%s'", url)
			else:
				payload = part.get_payload(decode=True)
				if payload is None:
					logging.warning("\t\t\tBody(html): payload is None -> feed '%s'", url)
				else:
					lines = payload.decode(charset).strip().split('\n')
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
			if re.match('^https?://[^ 	]+$', str(l['href']), re.IGNORECASE):
				feed = str(l['href'])
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

	return feed.strip() if feed else None


def get_feed_name_from_url(url):
	if not re.match(r'^https?://([^/]+)/?.*$', url):
		return None

	domain = re.sub(r'^https?://([^/]+)/?.*$', '\\1', url)
	slashes = url.count('/')
	if slashes <= 2 or (slashes == 3 and url[-1] == '/'):
		return domain

	url_noparams = url
	params = None

	if url.find('?') != -1:
		params = re.sub(r'^.*/.*(\?.*)$', '\\1', url)

		if params is not None and len(params) > 0:
			url_noparams = re.sub(r'^(.*/.*)\?.*$', '\\1', url)

	last_alphanum_part = re.sub(r'^.*/([0-9a-zA-Z_-]+)(\.(xml|feed|atom|rss|php))*/?$', '\\1', url_noparams)
	last_alphanum_part = last_alphanum_part.replace('_', '-')
	if params is None or len(params) <= 0:
		return domain + '--' + last_alphanum_part

	params_kv = params[1:].split('&')
	params_text = []
	for kv in params_kv:
		if kv.find('=') == -1:
			params_text.append(kv)
		else:
			params_text.append(kv.split('=')[1])
	return domain + '--' + last_alphanum_part + '--' + '--'.join(params_text)



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
				output = rss2email_delete_feed(email, feed_index)
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
		port     = get_config().get('smtp', 'port')
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
	logging.debug("Message to send to '%s':\n-- %s\n%s", to_addrs, subject, text)
	check_smtp()
	from_bot = get_config().get('message', 'from')
	msg = smtp_sender.build_text_message(from_bot, to_addrs, subject, text)
	smtp_sender.send_message(SMTP_CONNECTION, msg)
	logging.debug("Message sent")


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
	number_of_feeds = len(feeds)
	logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
				  'are' if number_of_feeds > 1 else 'is',
				  number_of_feeds,
				  's' if number_of_feeds > 1 else '',
				  email)
	if number_of_feeds:
		raise RuntimeError(
			"There should be no feed for a new subscription ! "
			"Got '%s' for user '%s'" % (number_of_feeds, email))
	feeds.config['DEFAULT']['to'] = email
	feeds.config['DEFAULT']['from'] = get_config().get('message', 'from')
	for k, v in get_config()['DEFAULT'].items():
		feeds.config['DEFAULT'][k] = v
	feeds.save()
	logging.debug("\t\tFeeds saved for '%s'", email)
	return i18n.t('rssbot.action_new_subscription', email=email)


def rss2email_remove_subscription(email):
	d_path = rss2email_get_data_dir_from_email(email)
	if isdir(d_path):
		shutil.rmtree(d_path)
	return i18n.t('rssbot.action_unsubscribed', email=email)


def rss2email_add_feed(email, url):
	name = get_feed_name_from_url(url)
	if not name:
		logging.error("\t\tFailed to get feed name for feed '%s'", url)
		return i18n.t('rssbot.action_feed_add_failed', url=url)

	try:
		logging.debug("\t\tCreating a temporary feed (name=%s, url=%s)",
					  name, url[:30] + ('…' if len(url) > 30 else ''))
		temp_feed = _feed.Feed(name=name, url=url)
		logging.debug("\t\tFetching the feed")
		parsed = temp_feed._fetch()
		logging.debug("\t\tChecking for errors")
		notices, warnings, errors = check_for_feed_errors(parsed)
	except Exception as exception:
		logging.error("\t\tFeed produced a '%s' exception: %s",
					  type(exception).__name__, exception)
		return i18n.t('rssbot.action_feed_add_failed', url=url)

	if notices:
		for notice in notices:
			logging.debug("\t\tFeed NOTICE: %s", notice)
	if warnings:
		for warning in warnings:
			logging.debug("\t\tFeed WARNING: %s", warning)
	if errors:
		for error in errors:
			logging.debug("\t\tFeed ERROR: %s", error)
	if warnings or errors:
		logging.debug("\t\tFeed '%s' is not valid. Not adding it.", url)
		return i18n.t('rssbot.action_feed_add_refused', url=url)

	logging.debug("\t\tAdding feed '%s' (%s) for '%s'", name, url, email)
	temp_feed = None
	feeds = get_feeds(email)
	number_of_feeds = len(feeds)
	logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
				  'are' if number_of_feeds > 1 else 'is',
				  number_of_feeds,
				  's' if number_of_feeds > 1 else '',
				  email)
	feeds.load(lock=True)
	logging.debug("\t\tSuccessfully loaded feeds (lock=True)")
	feed = feeds.new_feed(name=name, url=url, to=email)
	logging.debug("\t\tCreated the new feeds (name=%s, url=%s, to=%s)",
				  name, url[:30] + ('…' if len(url) > 30 else ''), email)
	feeds.save()
	number_of_feeds = len(feeds)
	logging.debug("\t\tNow there %s %d feed%s for '%s'",
				  'are' if number_of_feeds > 1 else 'is',
				  number_of_feeds,
				  's' if number_of_feeds > 1 else '',
				  email)
	logging.debug("\t\tFeeds saved for '%s'", email)
	return i18n.t('rssbot.action_feed_added', url=url)


def rss2email_delete_feed(email, index):
	logging.debug("\t\tDeleting feed '%d' for '%s'", index, email)
	feeds = get_feeds(email)
	number_of_feeds = len(feeds)
	logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
				  'are' if number_of_feeds > 1 else 'is',
				  number_of_feeds,
				  's' if number_of_feeds > 1 else '',
				  email)
	feeds.load(lock=True)
	logging.debug("\t\tSuccessfully loaded feeds (lock=True)")
	feed = feeds.index(index)
	logging.debug("\t\tFeed: %s", feed)
	feeds.remove(feed)
	logging.debug("\t\tFeed removed")
	feeds.save()
	number_of_feeds = len(feeds)
	logging.debug("\t\tNow there %s %d feed%s for '%s'",
				  'are' if number_of_feeds > 1 else 'is',
				  number_of_feeds,
				  's' if number_of_feeds > 1 else '',
				  email)
	logging.debug("\t\tFeeds saved for '%s'", email)
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

