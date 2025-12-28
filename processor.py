#!/usr/bin/env python
"""A library to process RSS feeds and turn them into email (using rss2email) and
also read email to manage RSS subscription."""

import re
import logging
import email
import email.header
import datetime
import smtplib
from os.path import join, isfile, isdir
import shutil
from bs4 import BeautifulSoup

from rss2email import feed as _feed # pylint: disable=import-error
from rss2email import feeds as _feeds # pylint: disable=import-error
import i18n # pylint: disable=import-error

import smtp_sender

# BEGIN -- import for function 'check_for_feed_errors'
# copy pasted from rss2email/feed.py
import socket as _socket # pylint: disable=wrong-import-order
_SOCKET_ERRORS = []
for e in ['error', 'herror', 'gaierror']:
    if hasattr(_socket, e):
        _SOCKET_ERRORS.append(getattr(_socket, e))
del e  # cleanup namespace
_SOCKET_ERRORS = tuple(_SOCKET_ERRORS)
import xml.sax as _sax # pylint: disable=wrong-import-order,wrong-import-position
import feedparser as _feedparser # pylint: disable=import-error,wrong-import-order,wrong-import-position
_feedparser.PREFERRED_XML_PARSERS = []
# END -- import for function 'check_for_feed_errors'


REGEX_EMAIL_WITH_NAME = re.compile('^ *"?[^"]+"? *<(?P<email>[^>]+)> *$')

SMTP_CONNECTION = None
CONFIG = None


###########################################
### Incoming email processing functions ###
###########################################

def get_email_sender(msg):
    """Parse the mail header 'From' to extract the send email."""
    from_who = str(email.header.make_header(email.header.decode_header(msg['From'])))
    email_with_name = REGEX_EMAIL_WITH_NAME.match(from_who)
    if email_with_name:
        from_who = email_with_name.group('email').strip().lower()
    return from_who


def parse_message(msg, subject_filter=None):
    """Parse an email message to extract:
    - Sender: who is the sender
    - Recipients: to whom it was sent
    - Date: when it was sent
    - Subject: what it is about
    - Action: what should be done (extracted from the subject)
    - Feed: is there a link to be treated as a feed source
    """

    # from
    from_who = get_email_sender(msg)

    # to
    #to_who = str(email.header.make_header(email.header.decode_header(msg['To'])))

    # date
    msg_date = msg['Date']
    date_tuple = email.utils.parsedate_tz(msg['Date'])
    if date_tuple:
        local_date = datetime.datetime.fromtimestamp(email.utils.mktime_tz(date_tuple))
        msg_date = local_date.strftime("%a, %d %b %Y %H:%M:%S")

    # subject
    subject = str(email.header.make_header(email.header.decode_header(msg['Subject'])))

    # action and feed
    action = '..skipped..'
    feed = ''
    if subject and (not subject_filter or subject.startswith(subject_filter)):

        # action
        action = subject.strip().lower()
        if subject_filter and subject.startswith(subject_filter):
            action = subject[len(subject_filter):].strip().lower()

        # body
        #body = msg['Body']
        feed = extract_feed_url_from_body(msg)
    elif subject and subject_filter and not subject.startswith(subject_filter):
        logging.debug("Subject '%s' do not starts with '%s': skiping",
                      subject, subject_filter)
    elif not subject:
        logging.debug("Empty subject: skiping")

    return msg_date, from_who, subject, action, feed


def process_message(num, msg, subject_filter=None):
    """Process a message."""
    msg_date, from_who, subject, action, feed = parse_message(msg, subject_filter=subject_filter)
    logging.info('< #%4s %10s [%25s] %40s %s %s', num.decode(), action,
                 msg_date, from_who, subject, ('(' + feed + ')' if feed else ''))
    return process_rss2email(from_who, subject, action, feed)


def process_rss2email(_email, subject, action, url): # pylint: disable=too-many-statements,too-many-branches
    """Manage RSS subscriptions."""
    subject = "Re: " + subject

    if not re.match('^[     ]*(' + '|'.join(get_actions()) + ')[     ]*$', action, re.IGNORECASE):
        if action == '..skipped..':
            return True
        logging.info("\t\tInvalid action '%s'.", action)
        logging.debug("\t\tAllowed actions in lang '%s': %s", i18n.get('locale'),
                      ', '.join(get_actions()))
        response = i18n.t('rssbot.error_invalid_action', action=action,
                          allowed_actions=', '.join(get_actions()))
        send_mail(_email, subject, response)
        logging.info("> %s", response)
        return True

    has_subscription = rss2email_has_subscriptions(_email)
    if not has_subscription and action != i18n.t('rssbot.subscribe'):
        response = i18n.t('rssbot.error_no_subscription',
            email=_email, service=get_config().get('service', 'name'),
            subscribe=i18n.t('rssbot.subscribe'))
        send_mail(_email, subject, response)
        logging.info("> %s", response)
        return True

    if i18n.t('rssbot.subscribe') == action:
        if has_subscription:
            response = i18n.t('rssbot.error_already_subscribed',
                email=_email, service=get_config().get('service', 'name')
            )
            send_mail(_email, subject, response)
            logging.info("> %s", response)
        else:
            output = rss2email_new_subscription(_email)
            send_mail(_email, subject, output)
            logging.info("> %s", output)

    elif i18n.t('rssbot.unsubscribe') == action:
        output = rss2email_remove_subscription(_email)
        send_mail(_email, subject, output)
        logging.info("> %s", output)

    elif i18n.t('rssbot.add') == action:
        if not url:
            response = i18n.t('rssbot.error_no_feed_found')
            send_mail(_email, subject, response)
            logging.info("> %s", response)
        elif rss2email_get_feed_index(_email, url) is not None:
            response = i18n.t('rssbot.error_existing_feed', url=url)
            send_mail(_email, subject, response)
            logging.info("> %s", response)
        else:
            output = rss2email_add_feed(_email, url)
            send_mail(_email, subject, output)
            logging.info("> %s", output)

    elif i18n.t('rssbot.delete') == action:
        if not url:
            response = i18n.t('rssbot.error_no_feed_found')
            send_mail(_email, subject, response)
            logging.info("> %s", response)
        else:
            feed_index = rss2email_get_feed_index(_email, url)
            if not feed_index:
                response = i18n.t('rssbot.error_no_existing_feed', url=url)
                send_mail(_email, subject, response)
                logging.info("> %s", response)
            else:
                output = rss2email_delete_feed(_email, feed_index)
                send_mail(_email, subject, output)
                logging.info("> %s", output)

    elif i18n.t('rssbot.list') == action:
        output = rss2email_list_feeds(_email)
        send_mail(_email, subject, output)
        logging.info("> (list of feeds)")
    else:
        logging.info("\tInvalid action '%s'. Skipping.", action)
    return True


def get_actions():
    """List available actions."""
    return [
        i18n.t('rssbot.subscribe'),
        i18n.t('rssbot.unsubscribe'),
        i18n.t('rssbot.add'),
        i18n.t('rssbot.delete'),
        i18n.t('rssbot.list')
    ]


def get_feeds(_email):
    """Return RSS feeds object ready to be processed."""
    d_path = rss2email_get_data_dir_from_email(_email)
    data_file = join(d_path, get_config().get('rss2email', 'data_filename'))
    config_file = join(d_path, get_config().get('rss2email', 'configuration_filename'))
    logging.debug("Loading feeds for '%s' (data:'%s', config:'%s')", _email, data_file, config_file)
    return _feeds.Feeds(datafile_path=data_file, configfiles=[config_file])


def sanitize_email(_email):
    """Sanitize an email string."""
    return _email.replace('/', '').replace(';', '').replace('"', '') \
                                  .replace("'", '').replace(' ', '')


def rss2email_get_data_dir_from_email(_email):
    """Create a user data directory path matching an email."""
    return join(get_config().get('rss2email', 'data_dir'), sanitize_email(_email))


def rss2email_has_subscriptions(_email):
    """Return True if the email match an existing subscription."""
    d_path = rss2email_get_data_dir_from_email(_email)
    return isdir(d_path) \
    and isfile(join(d_path, get_config().get('rss2email', 'configuration_filename'))) \
    and isfile(join(d_path, get_config().get('rss2email', 'data_filename')))


def rss2email_new_subscription(_email):
    """Handle a new user subscription."""
    logging.debug("\t\tNew subscription for '%s'", _email)
    feeds = get_feeds(_email)
    number_of_feeds = len(feeds)
    logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
                  'are' if number_of_feeds > 1 else 'is',
                  number_of_feeds,
                  's' if number_of_feeds > 1 else '',
                  _email)
    if number_of_feeds:
        raise RuntimeError(
            "There should be no feed for a new subscription ! "
            f"Got '{number_of_feeds}' for user '{_email}'")
    feeds.config['DEFAULT']['to'] = _email
    feeds.config['DEFAULT']['from'] = get_config().get('message', 'from')
    for key, val in get_config()['DEFAULT'].items():
        feeds.config['DEFAULT'][key] = val
    feeds.save()
    logging.debug("\t\tFeeds saved for '%s'", _email)
    return i18n.t('rssbot.action_new_subscription', email=_email)


def rss2email_remove_subscription(_email):
    """Handle the removal of a user subscription."""
    d_path = rss2email_get_data_dir_from_email(_email)
    if isdir(d_path):
        shutil.rmtree(d_path)
    return i18n.t('rssbot.action_unsubscribed', email=_email)


def rss2email_add_feed(_email, url):
    """Add an RSS feed source to the user feed list."""
    name = get_feed_name_from_url(url)
    if not name:
        logging.error("\t\tFailed to get feed name for feed '%s'", url)
        return i18n.t('rssbot.action_feed_add_failed', url=url)

    try:
        logging.debug("\t\tCreating a temporary feed (name=%s, url=%s)",
                      name, url[:30] + ('…' if len(url) > 30 else ''))
        temp_feed = _feed.Feed(name=name, url=url)
        logging.debug("\t\tFetching the feed")
        parsed = temp_feed._fetch() # pylint: disable=protected-access
        logging.debug("\t\tChecking for errors")
        notices, warnings, errors = check_for_feed_errors(parsed)
    except Exception as exception: # pylint: disable=broad-exception-caught
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

    logging.debug("\t\tAdding feed '%s' (%s) for '%s'", name, url, _email)
    temp_feed = None
    feeds = get_feeds(_email)
    number_of_feeds = len(feeds)
    logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
                  'are' if number_of_feeds > 1 else 'is',
                  number_of_feeds,
                  's' if number_of_feeds > 1 else '',
                  _email)
    feeds.load()
    logging.debug("\t\tSuccessfully loaded feeds")
    feeds.new_feed(name=name, url=url, to=_email)
    logging.debug("\t\tCreated the new feeds (name=%s, url=%s, to=%s)",
                  name, url[:30] + ('…' if len(url) > 30 else ''), _email)
    feeds.save()
    number_of_feeds = len(feeds)
    logging.debug("\t\tNow there %s %d feed%s for '%s'",
                  'are' if number_of_feeds > 1 else 'is',
                  number_of_feeds,
                  's' if number_of_feeds > 1 else '',
                  _email)
    logging.debug("\t\tFeeds saved for '%s'", _email)
    return i18n.t('rssbot.action_feed_added', url=url)


def rss2email_delete_feed(_email, index):
    """Handle the deletion of a feed source."""
    logging.debug("\t\tDeleting feed '%d' for '%s'", index, _email)
    feeds = get_feeds(_email)
    number_of_feeds = len(feeds)
    logging.debug("\t\tCurrently there %s %d feed%s for '%s'",
                  'are' if number_of_feeds > 1 else 'is',
                  number_of_feeds,
                  's' if number_of_feeds > 1 else '',
                  _email)
    feeds.load()
    logging.debug("\t\tSuccessfully loaded feeds")
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
                  _email)
    logging.debug("\t\tFeeds saved for '%s'", _email)
    return i18n.t('rssbot.action_feed_deleted', url=feed.url)


def rss2email_list_feeds(_email):
    """List the user RSS feeds."""
    logging.debug("\t\tListing feeds for '%s'", _email)
    output = []
    feeds = get_feeds(_email)
    feeds.load()
    for i,feed in enumerate(feeds):
        if feed.active:
            active_char = '*'
        else:
            active_char = ' '
        output.append(f'{i}: [{active_char}] {feed.name} ({feed.url})')
    return '\n'.join(output)


def rss2email_get_feed_index(_email, url):
    """Return the index of a feed in the list of feeds."""
    feeds = get_feeds(_email)
    feeds.load()
    for i, feed in enumerate(feeds):
        if feed.url == url:
            return i
    return None


def extract_feed_url_from_body(msg): # pylint: disable=too-many-branches
    """Parse an email body to extract an URL."""
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
                    logging.debug("\t\t\tBody(text): %d lines (%s) -> feed '%s'",
                                  len(lines), charset, url)
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
            logging.debug("\t\tBody skipped: %s (multipart: %s)",
                          part.get_content_type(), part.is_multipart())
    if not url and html:
        url = get_feed_from_content(html, True)
    return url


def get_feed_from_content(content, html=False):
    """Get an URL from a content, optionnaly HTML formatted."""
    feed = None
    lines = content
    if isinstance(content, str):
        lines = content.strip().split('\n')
    elif not isinstance(content, list):
        raise TypeError(
            "Parameter 'content' must be a string or a list but found '" +
            str(type(content)) + "'")
    if html:
        soup = BeautifulSoup('\n'.join(lines), 'html.parser')
        links = soup.find_all('a')
        for link in links:
            if re.match('^https?://[^     ]+$', str(link['href']), re.IGNORECASE):
                feed = str(link['href'])
                break

    if not html or not feed:
        for line in lines:
            match = re.search('(https?://[^     <>]+)', line, re.IGNORECASE)
            if match:
                found = match.group(1)
                feed = found
                if isinstance(found, list):
                    feed = found[0]
                break

    return feed.strip() if feed else None


def get_feed_name_from_url(url):
    """Create a (feed) name from an URL."""
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

    last_alphanum_part = re.sub(r'^.*/([0-9a-zA-Z]+)(\.(xml|feed|atom|rss|php))?/?$',
                                '\\1', url_noparams)
    if params is None or len(params) <= 0:
        return domain + '--' + last_alphanum_part

    params_kv = params[1:].split('&')
    params_text = []
    for keyval in params_kv:
        if keyval.find('=') == -1:
            params_text.append(keyval)
        else:
            params_text.append(keyval.split('=')[1])
    return domain + '--' + last_alphanum_part + '--' + '--'.join(params_text)


# a near copy-paste from rss2email/feed.py
# instead of logging notices, warnings and errors, it returns them
def check_for_feed_errors(parsed): # pylint: disable=too-many-branches
    """Ensure the feed has no errors, else handle them."""
    notices = []
    warnings = []
    errors = []

    status = getattr(parsed, 'status', 200)
    if status not in [200, 301, 302, 304, 307]:
        errors.append(f"HTTP status is not okay (status={status})")

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
        errors.append(f'sax parsing error: {exc}')
    elif (parsed.bozo and
          isinstance(exc, _feedparser.CharacterEncodingOverride)):
        warnings.append(
            f'incorrectly declared encoding: {exc}')
    elif (parsed.bozo and isinstance(exc, _feedparser.NonXMLContentType)):
        warnings.append(f'non XML Content-Type: {exc}')
    elif parsed.bozo or exc:
        if exc is None:
            exc = "can't process"
        errors.append(f'processing error: {exc}')

    if (status in [200, 302] and
        not parsed.entries and
        not version):
        errors.append('processing error')

    return notices, warnings, errors


def handle_incoming_msg_error(exception, msg):
    """Handle an incoming message error by sending a feedback email to the user."""
    logging.error("Catched an exception (program have aborted): %s", exception)
    _email = None

    try:
        _, _email, subject, _, feed = parse_message(msg)
        response = i18n.t('rssbot.error_exception',
            error=type(exception).__name__,
            message=subject + (' (' + feed + ')' if feed else ''),
            admin=get_config().get('service', 'admin')
        )
        subject = "Re: " + subject

    except Exception as inner_exception: # pylint: disable=broad-exception-caught
        logging.error("Catched an inner exception: %s", inner_exception)
        try:
            _email = get_email_sender(msg)
            subject = "Error"
            subject_prefix = get_config().get('message', 'subject_prefix', fallback=None)
            if subject_prefix is not None and len(subject_prefix) > 0:
                subject = subject_prefix + ' ' + subject
            response = i18n.t('rssbot.error_exception_fallback',
                              admin=get_config().get('service', 'admin'),
                              message=str(msg))
        except Exception as inner_inner_exception: # pylint: disable=broad-exception-caught
            logging.error("Catched an inner inner exception: %s", inner_inner_exception)

    if _email and subject and response:
        try:
            send_mail(_email, subject, response)
        except Exception as inner_exception: # pylint: disable=broad-exception-caught
            logging.error("Catched an inner exception: %s", inner_exception)
    else:
        logging.error(
            "Cannot send email back to user. Details: email='%s', "
            "subject='%s', response='%s'", _email, subject, response)


###########################################
### Outgoing email processing functions ###
###########################################

def send_mail(to_addrs, subject, text):
    """Send an email to the recipient with the specified subject and text."""
    global SMTP_CONNECTION # pylint: disable=global-variable-not-assigned
    logging.debug("Message to send to '%s':\n-- %s\n%s", to_addrs, subject, text)
    check_smtp()
    from_bot = get_config().get('message', 'from')
    msg = smtp_sender.build_text_message(from_bot, to_addrs, subject, text)
    smtp_sender.send_message(SMTP_CONNECTION, msg)
    logging.debug("Message sent")


# used by 'rssbot.feed_send' function overriding the send method in rss2email's feed
def send_message(recipient, msg, from_bot=None):
    """Send an email message to the recipient."""
    global SMTP_CONNECTION # pylint: disable=global-variable-not-assigned
    logging.debug("Message to send to '%s'", recipient)
    check_smtp()
    if from_bot is None:
        if get_config() is None:
            raise Exception( # pylint: disable=broad-exception-raised
                "No 'from' parameter and empty 'config' for Processor instance")
        from_bot = get_config().get('message', 'from')
    try:
        SMTP_CONNECTION.send_message(msg, from_bot, recipient.split(','))
        logging.debug("Message sent")
    except smtplib.SMTPDataError as exc:
        logging.error("\t\tFailed to send message to '%s' (from: %s): %s",
                      recipient, from_bot, exc)
    except smtplib.SMTPServerDisconnected as exc:
        logging.error("\t\tFailed to send message to '%s' (from: %s): %s",
                      recipient, from_bot, exc)
        logging.error("\t\tMore detail: msg = %s", msg)
        for key in ['From', 'To', 'Return-path']:
            if key in msg:
                logging.error("\t\tMore detail: msg[%s] = '%s'", key, msg[key])
        # TODO: implements
        # logging.info("\t\treconnecting to SMTP ...")


# fake to debug
def send_mail_debug(_, subject, text):
    """Faking to send an email."""
    logging.debug("Message to send:\n-- %s\n%s", subject, text)


######################
### SMTP functions ###
######################

def check_smtp():
    """Raise an error if there is not global SMTP connection defined."""
    global SMTP_CONNECTION # pylint: disable=global-variable-not-assigned
    if not SMTP_CONNECTION:
        raise RuntimeError("You must init an SMTP connection with init_smtp() "
                           "before processing messages")


def init_smtp(hostname=None, port=None, username=None, password=None, ssl=None):
    """Establish an SMTP connection."""
    global SMTP_CONNECTION # pylint: disable=global-statement
    if not SMTP_CONNECTION:
        if hostname is None:
            hostname = get_config().get('smtp', 'hostname')
        if port is None:
            port = get_config().get('smtp', 'port')
        if ssl is None:
            ssl = get_config().getboolean('smtp', 'ssl', fallback=False)
        if username is None:
            username = get_config().get('account', 'username', fallback=None)
        if password is None:
            password = get_config().get('account', 'password', fallback=None)

        # support for 'server:port'
        pos = hostname.find(':')
        if 0 <= pos:
            # Strip port out of server name
            port = int(hostname[pos+1:])
            hostname = hostname[:pos]

        try:
            logging.info(
                "Establishing SMTP connection to '%s:%s' (ssl: %s) with "
                "user '%s'", hostname, port, ssl, username)
            SMTP_CONNECTION = smtp_sender.open_connection(
                hostname, port, username, password, ssl=ssl)
            return SMTP_CONNECTION
        except smtplib.SMTPException as smtp_exc:
            logging.error(
                "Failed to connect to SMTP server '%s:%s' (ssl: %s) with "
                "user '%s' (%s)", hostname, port, ssl, username, smtp_exc)
    return False

def close_smtp():
    """Close the global SMTP connection."""
    global SMTP_CONNECTION # pylint: disable=global-statement
    if SMTP_CONNECTION:
        try:
            smtp_sender.close_connection(SMTP_CONNECTION)
        except smtplib.SMTPServerDisconnected:
            pass
    SMTP_CONNECTION = None


#######################
### Other functions ###
#######################

def get_config():
    """Return the global configuration."""
    global CONFIG # pylint: disable=global-variable-not-assigned
    return CONFIG


def set_config(config):
    """Set the global config."""
    global CONFIG # pylint: disable=global-statement
    CONFIG = config


def set_locale(locale):
    """Set the local used for translation (with i18n)."""
    logging.debug("Service will operate with language: %s (fallback: %s)", locale, 'en')
    i18n.set('locale', locale)
    i18n.set('fallback', 'en')


def load_translations(path):
    """Load a translation file."""
    logging.debug("Loading translations from: '%s'", path)
    i18n.load_path.append(path)
