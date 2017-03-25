# rssbot
Convert RSS to email and manage users subscriptions and feeds through email messages.

## Requirements
A mailbox than can be connected to with an IMAP server (to read message) and SMTP server (to send message). Both servers needs to accept SSL connections.
A server with python3 to install rssbot.

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

### (Optional) Patching rss2email

In order to avoid failure when RSS feeds are protected with an invalid SSL certificate, you can disable SSL certificate verification by patching an rss2email file.

Open the file :
```
rssbot/lib/python3.5/site-packages/rss2email/feed.py
```
_Replace `python3.5` by your python version._

And add the following lines, after the last import line `from . import util as _util` :
```
# begin patch: disable SSL certificate verification
# @see: http://stackoverflow.com/a/35960702
import ssl
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context
# end patch
```

## Usage

Run `python3 rssbot.py`.

```
usage: rssbot.py [-h] [-r] [-l] CONFIG

Convert RSS to email and manage users subscriptions and feeds through email messages.

positional arguments:
  CONFIG         The configuration file

optional arguments:
  -h, --help           show this help message and exit
  -r, --run-all        Fetch and send all feeds of all users
  -l, --list-subjects  List manamgent message predefined subjects/actions translated

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
python3 <path_to>/rssbot.py -r
```
I recommend planing it once a day, at night.

To read and process management messages, add that to your crontab (or like) :
```
python3 <path_to>/rssbot.py
```
I recommend to plan it to every 15 minutes.


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
level = INFO
format = %%(asctime)-15s %%(levelname)-8s %%(message)s

[DEFAULT]
email-protocol = smtp
smtp-auth = True
smtp-username = rssbot@example.net
smtp-password = s3cr3tp4ssWd
smtp-server = mail.gandi.net:465
smtp-ssl = True
smtp-ssl-protocol = SSLv3
```

### Sections explained

- **imap** : The IMAP server hostname and port, to read from management messages. IMAP connection are always made with SSL.
- **smtp** : The SMTP server hostname and port, to send management answer messages. SMTP connection are always made with SSL.
- **account** : The credentials to connect with, to IMAP and SMTP (assuming they use the same)
- **mailbox** : The inbox parameters, like the Inbox name in the IMAP server.
- **message** : The outgoing management anwser message parameters, like the sender address and the subject's prefix
- **rss2email** : The parameters to manage rss2email user directories and files
- **service** : The service parameters, like its name and its language
- **log** : The logging parameters
- **DEFAULT** : The default configuration parameters that will be used by each user of rss2email

## Notes

It uses logging as output, so adjust verbosity by adjusting the log level.

It was made and tested on Linux without any knowledge of Windows environment, so it may or may not work on Windows.

It was not unit-tested, but was exhaustively tested with real cases usage.

