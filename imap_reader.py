#!/usr/bin/env python
"""Use imaplib library to read email message."""

import imaplib
import email
import configparser
import logging
import rss2email


def get_config(path):
    """Get a Config object from a file path."""
    config = configparser.ConfigParser()
    config.read([path])
    return config


def open_connection(hostname, port, username, password):
    """Open an IMAP connection and login."""
    # Connecting
    logging.debug("Openning IMAP SSL connection to '%s:%s'", hostname, port)
    connection = imaplib.IMAP4_SSL(host=hostname, port=port)

    # Login to our account
    logging.debug("Login IMAP with user '%s'", username)
    connection.login(username, password)
    return connection


def get_messages(_conn):
    """Get messages/emails from IMAP connection."""
    _type, _data = _conn.search(None,'(UNSEEN)')
    for _num in _data[0].split():
        _rv, _data = _conn.fetch(_num,'(RFC822)')
        if _rv != 'OK':
            logging.error("Failed to get message '%s'", _num)
            return
        _msg = email.message_from_bytes(_data[0][1])
        yield (_num, _msg)


def mark_msg_as_read(_conn, _num):
    """Mark message as read."""
    _conn.store(_num,'+FLAGS','\\Seen')
    logging.debug('\t\tFlaged as READ')


def mark_msg_as_not_read(_conn, _num):
    """Mark message as not read."""
    _conn.store(_num,'-FLAGS','\\Seen')
    logging.debug('\t\tFlaged as NOT READ')
