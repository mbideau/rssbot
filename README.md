# rssbot
Convert RSS to email and manage users subscriptions and feeds through email messages.


## Requirements
A mailbox than can be connected to with an IMAP server (to read message) and SMTP server (to send message).
A Linux server with _python3_.


## Installation

Clone the sources :
```
~> git clone https://github.com/mbideau/rssbot.git rssbot
```

Install packages requirements (on _Ubuntu_/_Debian_):
```
~> apt install --no-install-recommends python3-pip
```

Create a python virtual environment :
```
~> python3 -m venv rssbot
```

Install required python dependencies :
```
~> rssbot/bin/pip install rss2email html2text feedparser beautifulsoup4 python-i18n pyyaml
```

## Usage

Run `rssbot/bin/python rssbot/rssbot.py --help`.

```
usage: rssbot.py [-h] [-m] [-u USER] [-a] [-l] CONFIG

Convert RSS to email and manage users subscriptions and feeds through email
messages.

positional arguments:
  CONFIG                The configuration file

optional arguments:
  -h, --help            show this help message and exit
  -m, --manage          Manage subscription of users
  -u USER, --user USER  Fetch and send all feeds of specified user
  -a, --fetch-all       Fetch and send all feeds of all users
  -l, --list-subjects   List managment message predefined subjects/actions
                        translated
```

### Management messages

To manage users subscription and feeds, you send email message to the IMAP mailbox with a specific syntax.
Basically, you use a predefined subject, and, if required, a feed url in the mail body.
Predefined subjects are :

- **Subscribe** : the user subscribe to the service, its email is registered.
- **Unsubscribe** : the user unsubscribe to the service, all its feeds are deleted.
- **Add** : the user add a feed to its collection. The feed url must be given in the mail body.
- **Delete** : the user delete a feed to its collection. The feed url must be given in the mail body.
- **List** : the user list its feeds collection.

Every subject is translated according to the 'lang' parameter defined in the configuration file.   
The translations files must exists in `locales/rssbot.<locale>.yml`.  
To list the available subjects/actions in the choosen language, run `python 3 rssbot.py -l`.


### Planed execution

In order to fetch RSS feeds and send message, add the following command to your crontab (or like) :
```
rssbot/bin/python rssbot/rssbot.py --fetch-all
```
I recommend planing it once a day, at night.

To read and process management messages, add that to your crontab (or like) :
```
rssbot/bin/python rssbot/rssbot.py --manage
```
I recommend to plan it to every 15 minutes if you have a lot of users, else every hour.
Personaly, I plan it every night (I only have a few users).


## Sample configuration

```
[imap]
hostname =  mail.gandi.net
port = 993

[smtp]
hostname =  mail.gandi.net
port = 587

[account]
username = rssbot@example.net
password = s3cr3tp4ssWd

[mailbox]
inbox = INBOX
subject_filter = [add RSS feed]

[message]
from = rssbot@example.net
subject_prefix = [rss2email]

[rss2email]
data_dir = /srv/rss2email
configuration_filename = configuration.cfs
data_filename = data.json

[service]
name = rss2email
lang = fr
admin = admin@example.net

[log]
level = INFO
format = %%(asctime)-15s    %%(levelname)-8s %%(message)s

[DEFAULT]
html-mail = True
use-css = True
email-protocol = smtp
smtp-auth = True
smtp-username = rssbot@example.net
smtp-password = s3cr3tp4ssWd
smtp-server = mail.gandi.net:587
```

### Sections explained

- **imap** : The IMAP server hostname and port, to read from management messages. IMAP connection are always made with SSL.
- **smtp** : The SMTP server hostname and port, to send management answer messages. SMTP connection are always made with SSL.
- **account** : The credentials to connect with, to IMAP and SMTP (assuming they use the same)
- **mailbox** : The inbox parameters, like the Inbox name in the IMAP server.
- **message** : The outgoing management anwser message parameters, like the sender address and the subject's prefix
- **rss2email** : The parameters to manage rss2email user directories and files
- **service** : The service parameters, like its name, its language and its administrator contact
- **log** : The logging parameters
- **DEFAULT** : The default configuration parameters that will be used by each user of rss2email


## Notes

It uses logging as output, so adjust verbosity by adjusting the log level.

It was made and tested on Linux without any knowledge of Windows environment, so it may or may not work on Windows.

It was not unit-tested, but was exhaustively tested with real cases usage.

It is in production for myself since 2016 with a few users since end of 2019.
