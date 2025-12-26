#!/usr/bin/env python
"""Read RSS feeds and turn them into email, also read email to manage
RSS subscriptions."""

import argparse
import configparser
import os
import logging
import sys
import types

from rss2email import config as _config # pylint: disable=import-error
from rss2email import feeds as _feeds # pylint: disable=import-error
from rss2email import error as _error # pylint: disable=import-error
from rss2email import email as _email # pylint: disable=import-error

import processor
import imap_reader

def get_config(_path):
    """Get a Config object from a file path."""

    if not os.path.isfile(_path):
        sys.stderr.write(
            f"[ERROR] Configuration file '{_path}' doesn't exist\n")
        sys.exit(2)

    global_config = configparser.ConfigParser()
    with open(_path, encoding='utf8') as fd_config:
        global_config.read_file(fd_config)
    return global_config


# override the feed send method to reuse the SMTP connexion
def feed_send(self, sender, message): # pylint: disable=unused-argument
    """Send an email containing the RSS content."""
    section = self.section
    if section not in self.config:
        section = 'DEFAULT'
    protocol = self.config.get(section, 'email-protocol')
    logging.debug('send %s message for %s', protocol, self)
    if protocol == 'smtp':
        from_bot = self.config.get(section, 'from')
        processor.send_message(self.to, message, from_bot=from_bot)
    else:
        _email.send(recipient=self.to, message=message, config=self.config, section=section)


def fetch_feeds_and_send_email(global_config, _users): # pylint: disable=too-many-locals
    """Fetch user's feeds and send them by email."""

    # for each user
    for user, udir in _users.items(): # pylint: disable=too-many-nested-blocks
        logging.info("\tUser: %s (%s)", user, udir)
        data_file = os.path.join(udir, global_config.get('rss2email', 'data_filename'))
        config_file = os.path.join(udir, global_config.get('rss2email', 'configuration_filename'))
        feeds_default_config = _config.Config()
        feeds_default_config['DEFAULT'] = _config.CONFIG['DEFAULT']
        # run each feed (fetch then send)
        feeds = _feeds.Feeds(
            datafile_path=data_file, configfiles=[config_file],
            config=feeds_default_config)
        logging.debug("\t\tLoading feeds ...")
        feeds.load()
        if feeds:
            # open an SMTP connexion, else fetching is useless
            hostname = feeds.config.get('DEFAULT', 'smtp-server')
            port     = feeds.config.get('DEFAULT', 'smtp-port')
            ssl         = feeds.config.getboolean('DEFAULT', 'smtp-ssl', fallback=False)
            username = feeds.config.get('DEFAULT', 'smtp-username', fallback=None)
            password = feeds.config.get('DEFAULT', 'smtp-password', fallback=None)
            processor.init_smtp(
                hostname=hostname, port=port, username=username,
                password=password, ssl=ssl)
            try:
                logging.debug("\t\t%d feeds to fetch ...", len(feeds))
                save_feeds = True
                for feed in feeds:
                    if feed.active:
                        # override the send method (local to the object)
                        # to reuse SMTP connection
                        # pylint: disable=protected-access
                        feed._send = types.MethodType(feed_send, feed)
                        try:
                            logging.info("\t\tFetching: %s", feed.name)
                            feed.run(send=True)
                        except _error.SMTPAuthenticationError as exc:
                            logging.error(
                                "\t\tCatched an '%s' exception "
                                "(fetching feed aborted): %s",
                                type(exc).__name__, exc)
                            logging.info(
                                "\t\tStop fetching feeds "
                                "(they won't be saved, so "
                                "they could be fetched later)")
                            save_feeds = False
                            break
                        except Exception as exception: # pylint: disable=broad-exception-caught
                            logging.error(
                                "\t\tCatched an '%s' exception "
                                "(fetching feed aborted): %s",
                                type(exception).__name__, exception)
                if save_feeds:
                    logging.info("\t\tSaving feeds ...")
                    feeds.save_feeds()
                else:
                    logging.info("\t\tNot saving feeds")
            finally:
                # close smtp connection
                processor.close_smtp()
        else:
            logging.info("\t\tNo feed")


def list_user_commands(global_config):
    """List the available commands/actions."""

    # set config for processor module
    processor.set_config(global_config)

    # load translations and set locale
    locales_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), 'locales')
    processor.load_translations(locales_dir)
    locale = global_config.get('service', 'lang')
    processor.set_locale(locale)

    print('\n'.join(map(lambda x: x.title(), processor.get_actions())))


def manage_subscriptions_and_feeds_list(global_config):
    """Manage user subscriptions and feeds list."""

    logging.info("Processing management messages ...")

    # get connection parameters
    hostname       = global_config.get('imap', 'hostname')
    port           = global_config.get('imap', 'port')
    username       = global_config.get('account', 'username')
    password       = global_config.get('account', 'password')
    inbox_name     = global_config.get('mailbox', 'inbox')
    subject_filter = global_config.get('mailbox', 'subject_filter')

    # open connection
    imap_conn = imap_reader.open_connection(hostname, port, username, password)
    if not imap_conn:
        logging.error("Failed to login to '%s:%s' with user '%s'", hostname, port, username)
        sys.exit(1)

    # select mailbox
    if inbox_name and ' ' in inbox_name and (inbox_name[0] != '"' or inbox_name[-1] != '"'):
        inbox_name = '"' + inbox_name + '"'
    try:
        logging.info("Selecting IMAP folder '%s'", inbox_name)
        res, _ = imap_conn.select(inbox_name)
    except Exception as exc: # pylint: disable=broad-exception-caught
        logging.error("Failed to select INBOX '%s' (%s)", inbox_name, exc)
        sys.exit(1)
    if res != 'OK':
        logging.error("Failed to select INBOX '%s' (%s)", inbox_name, res)
        imap_conn.close()
        sys.exit(1)

    # set config for processor module
    processor.set_config(global_config)

    # open smtp connection
    processor.init_smtp()

    # load translations and set locale
    locales_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)),
                               'locales')
    processor.load_translations(locales_dir)
    locale = global_config.get('service', 'lang')
    processor.set_locale(locale)

    # process messages
    logging.debug("Processing mailbox ...")

    try:

        for num, msg in imap_reader.get_messages(imap_conn):
            if processor.process_message(num, msg, subject_filter=subject_filter):
                imap_reader.mark_msg_as_read(imap_conn, num)
            else:
                imap_reader.mark_msg_as_not_read(imap_conn, num)
            #imap_reader.mark_msg_as_not_read(imap_conn, num)

    except Exception as exception: # pylint: disable=broad-exception-caught
        processor.handle_incoming_msg_error(exception, msg)

    finally:

        # closing mailbox
        logging.debug("Closing IMAP mailbox ...")
        imap_conn.close()

        # close smtp connection
        processor.close_smtp()

        logging.debug("Logging out IMAP")
        imap_conn.logout()


# main program
if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="Convert RSS to email and manage users subscriptions and "
                    "feeds through email messages."
    )
    parser.add_argument('config', metavar='CONFIG',
                        help="The configuration file")
    parser.add_argument('-m', '--manage', dest='manage', action='store_true',
                        help="Manage subscription of users")
    parser.add_argument('-u', '--user', dest='user',
                        help="Fetch and send all feeds of specified user")
    parser.add_argument('-a', '--fetch-all', dest='fetch_all',
                        action='store_true',
                        help="Fetch and send all feeds of all users")
    parser.add_argument('-l', '--list-subjects', dest='list_subjects',
                        action='store_true',
                        help="List managment message predefined subjects/"
                             "actions translated")
    args = parser.parse_args()

    # get configuration
    config = get_config(args.config)

    # set the log level and log format accordingly
    log_level = config.get('log', 'level').upper()
    log_format = config.get('log', 'format')
    log_stream = sys.stdout
    if log_level == 'DEBUG':
        logging.basicConfig(stream=log_stream, level=logging.DEBUG, format=log_format)
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('rss2email').setLevel(logging.DEBUG)
    elif log_level == 'INFO':
        logging.basicConfig(stream=log_stream, level=logging.INFO, format=log_format)
    elif log_level == 'WARNING':
        logging.basicConfig(stream=log_stream, level=logging.WARNING, format=log_format)
    elif log_level == 'ERROR':
        logging.basicConfig(stream=log_stream, level=logging.ERROR, format=log_format)
    else:
        sys.stderr.write("[ERROR] Invalid log level '" + log_level + "'\n")
        sys.exit(2)

    logging.debug("Loaded configuration from file %s", args.config)

    # fetch and send
    if args.fetch_all or args.user:

        logging.info("Fetching and sending feeds ...")
        users = {}

        data_dir = config.get('rss2email', 'data_dir')
        logging.debug("From data dir: '%s'", data_dir)

        # all users
        if args.fetch_all:

            # for each user's dir
            for d in os.listdir(data_dir):
                d_path = os.path.join(data_dir, d)
                if os.path.isdir(d_path) and '@' in d:
                    users[d] = d_path

        # one user
        if args.user:

            d_path = os.path.join(data_dir, args.user)
            if os.path.isdir(d_path) and '@' in args.user:
                users[args.user] = d_path
            else:
                logging.info("User '%s' not found", args.user)

        # fetch and send
        fetch_feeds_and_send_email(config, users)

    # list subjects
    elif args.list_subjects:

        list_user_commands(config)

    # management messages
    elif args.manage:

        manage_subscriptions_and_feeds_list(config)

    # no argument
    else:

        # display help message
        parser.print_help()
