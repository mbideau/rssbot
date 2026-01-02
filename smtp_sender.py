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

    logging.info(
        "Establishing SMTP connection to '%s:%s' (ssl: %s) with "
        "user '%s'", hostname, port, ssl, username)
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

        if username or password:
            if not ssl:
                logging.debug("Starting SMTP TLS session")
                connection.starttls(context=context)
            logging.debug("Login SMTP with user '%s'", username)
            connection.login(username, password)

    except KeyboardInterrupt:
        logging.info("User interrupted the connection process")
        return False

    except smtplib.SMTPException as smtp_exc:
        logging.error(
            "Failed to connect to SMTP server '%s:%s' (ssl: %s) with "
            "user '%s' (%s)", hostname, port, ssl, username, smtp_exc)
        return False

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


def send_message(conn, msg, prefix='\t\t'):
    """Send the message through SMTP."""
    logging.debug('Sending SMTP message')
    msg_desc = (prefix +
        '> ' + (msg['Subject'] if 'Subject' in msg else '(no subject)') +
        ' -> ' + (msg['To'] if 'To' in msg else '(no recipient)'))
    logging.info(msg_desc)
    conn.send_message(msg)


def close_connection(conn):
    """Close the SMTP connection."""
    logging.info("Closing SMTP connection ...")
    conn.quit()
