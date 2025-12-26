# -*- coding: utf-8 -*-
"""Test SMTP connection by sending an Hello world email."""

import argparse
import logging
import configparser
import smtp_sender

parser = argparse.ArgumentParser()
parser.add_argument('recipient', help="Email to send test message to")
parser.add_argument('-c', '--config', default='configuration.ini',
                    help="Path to the configuration file. "
                         "Default: configuration.ini")
parser.add_argument('-s', '--subject', default='Test message',
                    help="Subject of the test message. Default: Test message")
parser.add_argument('-m', '--message', default='Hello world !\n',
                    help="Content of the test message. Default: Hello world !")
args = parser.parse_args()

testlog = logging.getLogger()
hd = logging.StreamHandler()
hd.setFormatter(logging.Formatter('%(message)s'))
testlog.addHandler(hd)
testlog.setLevel(logging.DEBUG)

testconfig = config = configparser.ConfigParser()
with open(args.config, encoding='utf8') as fd_config:
    config.read_file(fd_config)

# test message
sender = testconfig.get('message', 'from')
recipient = args.recipient
subject = args.subject
content = args.content

# SMTP send
smtp_hostname = testconfig.get('smtp', 'hostname')
smtp_port     = testconfig.get('smtp', 'port')
smtp_username = testconfig.get('account', 'username')
smtp_password = testconfig.get('account', 'password')
smtp_ssl      = testconfig.get('smtp', 'ssl')

smtp_ssl_bool = testconfig.getboolean('DEFAULT', 'smtp-ssl', fallback=False)
message = smtp_sender.build_text_message(sender, recipient, subject, content)
testlog.info("Openning SMTP connection using account '%s' on '%s:%s' (ssl: %s)",
             smtp_username, smtp_hostname, smtp_port, smtp_ssl_bool)
connection = smtp_sender.open_connection(smtp_hostname, smtp_port, smtp_username,
                                         smtp_password, smtp_ssl_bool)
smtp_sender.send_message(connection, message)
testlog.info("Sending a test message to '%s'", recipient)
smtp_sender.close_connection(connection)
