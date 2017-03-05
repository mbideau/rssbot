# rssbot
Convert RSS to email and manage users subscriptions and feeds through email messages.

## Installation

Clone the sources :
```
git clone https://github.com/mbideau/rssbot.git rssbot
```

Install packages requirements :
```
apt install --no-install-recommends python3-pip
```

Create a python virtual environment :
```
python3 -m venv rssbot
```

Install required python dependencies :
```
pip install rss2email
pip install html2text
pip install feedparser
pip install beautifulsoup4
pip install python-i18n
pip install pyyaml
```

## Usage

Run `python3 rssbot.py`.

```
usage: rssbot.py [-h] [-r] CONFIG

Convert RSS to email and manage users subscriptions and feeds through email messages.

positional arguments:
  CONFIG         The configuration file

optional arguments:
  -h, --help     show this help message and exit
  -r, --run-all  Fetch and send all feeds of all users
```

## Sample configuration

```
[imap]
hostname =  mail.gandi.net
port = 993

[smtp]
hostname =  mail.gandi.net
port = 465

[account]
username = rssbot@example.net
password = s3cr3tp4ssWd

[mailbox]
inbox = INBOX

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

[log]
level = DEBUG
format = %%(levelname)-8s %%(message)s

[DEFAULT]
email-protocol = smtp
smtp-auth = True
smtp-username = rssbot@example.net
smtp-password = s3cr3tp4ssWd
smtp-server = mail.gandi.net:465
smtp-ssl = True
smtp-ssl-protocol = SSLv3
```

## Notes

It uses logging as output, so adjust verbosity by adjusting the log level.

It was made and tested on Linux without any knowledge of Windows environment, so it may or may not work on Windows.

It was not unit-tested, but was exhaustively tested with real cases usage.

