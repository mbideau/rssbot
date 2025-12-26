#!/usr/bin/env python
"""Send email through an SMTP connection."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import ssl as _ssl

def open_connection(hostname, port, username, password, ssl = False):
    """Open an SMTP connection, optionnaly through SSL, and login."""

    # support for 'server:port'
    pos = hostname.find(':')
    if 0 <= pos:
        # Strip port out of server name
        port = int(hostname[pos+1:])
        hostname = hostname[:pos]

    logging.debug("Openning SMTP connection to '%s:%s'", hostname, port)
    try:
        if ssl or (username or password):
            logging.debug("Creating SMTP SSL context")
            context = _ssl.create_default_context()
        if ssl:
            logging.debug("Starting SMTP SSL session")
            connection = smtplib.SMTP_SSL(host=hostname, port=port, context=context)
        else:
            logging.debug("Starting SMTP session (no SSL)")
            connection = smtplib.SMTP(host=hostname, port=port)
    except KeyboardInterrupt: # pylint: disable=try-except-raise
        raise
    if username or password:
        try:
            if not ssl:
                logging.debug("Starting SMTP TLS session")
                connection.starttls(context=context)
            logging.debug("Login SMTP with user '%s'", username)
            connection.login(username, password)
        except KeyboardInterrupt: # pylint: disable=try-except-raise
            raise
    return connection


def build_text_message(from_who, to_addrs, subject, text):
    """Build a MIMEText message with From, To and Subject fields."""
    msg = MIMEText(text, 'plain')
    msg['From'] = from_who
    msg['To'] = to_addrs
    msg['Subject'] = subject
    return msg


def build_html_plus_text_message(from_who, to_addrs, subject, text, html):
    """Build an HTML (MIMEMultipart) message with From, To and Subject fields
    plus attachments."""
    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['From'] = from_who
    msg['To'] = to_addrs
    msg['Subject'] = subject
    # Create the body of the message (a plain-text and an HTML version).
    # Record the MIME types of both parts - text/plain and text/html
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    # Attach parts into message container.
    # According to RFC 2046, the last part of a multipart message, in this case
    # the HTML message, is best and preferred.
    msg.attach(part1)
    msg.attach(part2)
    return msg


def send_message(conn, msg):
    """Send the message through SMTP."""
    logging.debug('Sending SMTP message ...')
    conn.send_message(msg)


def close_connection(conn):
    """Close the SMTP connection."""
    logging.debug("Closing SMTP connection ...")
    conn.quit()
