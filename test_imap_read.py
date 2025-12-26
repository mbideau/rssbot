# -*- coding: utf-8 -*-
"""Test IMAP connection by reading an email from an inbox."""

import argparse
import configparser
import datetime
import email
import email.header
import imaplib
import logging
import sys

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', default='configuration.ini',
                    help="Path to the configuration file. "
                         "Default: configuration.ini")
parser.add_argument('-f', '--flag', default='UNSEEN',
                    help="Flag to specify the type of message to read. "
                         "Default: UNSEEN")
parser.add_argument('-l', '--limit', default=10, type=int,
                    help="Maximum number of email to read. "
                         "Default: 10")
args = parser.parse_args()

testlog = logging.getLogger()
hd = logging.StreamHandler()
hd.setFormatter(logging.Formatter('%(message)s'))
testlog.addHandler(hd)
testlog.setLevel(logging.DEBUG)

testconfig = config = configparser.ConfigParser()
with open(args.config, encoding='utf8') as fd_config:
    config.read_file(fd_config)

# IMAP read
hostname   = testconfig.get('imap', 'hostname')
port       = testconfig.get('imap', 'port')
username   = testconfig.get('account', 'username')
password   = testconfig.get('account', 'password')
inbox_name = testconfig.get('mailbox', 'inbox')

# Connecting
testlog.debug("Openning IMAP SSL connection to '%s:%s'", hostname, port)
imap_conn = imaplib.IMAP4_SSL(host=hostname, port=port)
if not imap_conn:
    testlog.error("Failed to connect to '%s:%s'", hostname, port)
    sys.exit(1)

# Login to our account
testlog.debug("Login IMAP with user '%s'", username)
if not imap_conn.login(username, password):
    testlog.error("Failed to login with '%s'", username)
    sys.exit(1)

# list folders
testlog.debug("Getting folders ...")
_, folders = imap_conn.list()
for folder in folders:
    logging.debug(" - %s", folder.decode())

# select mailbox
if inbox_name and ' ' in inbox_name and (
        inbox_name[0] != '"' or inbox_name[-1] != '"'):
    inbox_name = '"' + inbox_name + '"'
try:
    rv, data = imap_conn.select(inbox_name)
except Exception as exc: # pylint: disable=broad-exception-caught
    testlog.error("Failed to select INBOX '%s' (%s)", inbox_name, exc)
    sys.exit(1)
if rv != 'OK':
    testlog.error("Failed to select INBOX '%s' (%s)", inbox_name, rv)
    imap_conn.close()
    sys.exit(1)
testlog.debug("Selected Inbox: '%s'", inbox_name)

def get_messages(_conn, flag='UNSEEN'):
    """Get messages/emails from IMAP connection."""
    _type, _data = _conn.search(None, f'({flag})')
    for _num in _data[0].split():
        _rv, _data = _conn.fetch(_num,'(RFC822)')
        if _rv != 'OK':
            testlog.error("Failed to get message '%s'", _num)
            return
        _msg = email.message_from_bytes(_data[0][1])
        yield (_num, _msg)

def parse_message(_msg):
    """Parse an email message."""

    # from
    from_who = str(
        email.header.make_header(email.header.decode_header(_msg['From'])))

    # date
    msg_date = _msg['Date']
    date_tuple = email.utils.parsedate_tz(_msg['Date'])
    if date_tuple:
        local_date = datetime.datetime.fromtimestamp(
            email.utils.mktime_tz(date_tuple))
        msg_date = local_date.strftime("%a, %d %b %Y %H:%M:%S")

    # subject
    subject = str(
        email.header.make_header(email.header.decode_header(_msg['Subject'])))

    return msg_date, from_who, subject

COUNT = 0
testlog.debug("Reading %s messages ...", args.flag)
for num, msg in get_messages(imap_conn, args.flag):
    try:
        when, who, about = parse_message(msg)
        testlog.info('< #%4s %10s [%40s] %s', num.decode(), when, who, about)
    except Exception as exc: # pylint: disable=broad-exception-caught
        testlog.error("%s. Failed to process message [%s] %s", exc, num.decode(), msg)
    if args.flag == 'UNSEEN':
        imap_conn.store(num,'-FLAGS','\\Seen') # re-flag message as UNSEEN
        #testlog.debug("Flaging message [%s] as UNSEEN", num.decode())
    COUNT += 1
    if COUNT == args.limit:
        testlog.debug("Reached limit '%d', stoping.", args.limit)
        break
testlog.debug("Done.")
