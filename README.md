# rssbot
Convert RSS to email and manage users subscriptions and feeds through email messages.


## Requirements
A mailbox than can be connected to with an IMAP server (to read message) and SMTP server (to send message). Both servers needs to accept SSL connections.  
A Linux server with _python3_ (>= _3.7_ is recommended to avoid SSL issues described below).


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


### Attention: *python3.5* have a bug in its SSL implementation or dependencies

I had an unsolvable issue with some (not all) servers SSL connexions that raised the following python exception:
```python
~> python3.5
Python 3.5.3 (default, Sep 27 2018, 17:25:39)
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import ssl
>>> ssl.get_server_certificate(('postmarketos.org', 443))
..truncated..
ssl.SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:720)
```

I have tried so many workarounds that I can't remember all of them. Some of them where:

- testing with the _openssl_ binary
  ```
  ~> openssl s_client -connect postmarketos.org:443 </dev/null
  CONNECTED(00000003)
  ..truncated..
  Peer signing digest: SHA512
  Server Temp Key: ECDH, P-384, 384 bits
  ..truncated..
  New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384
  ..truncated..
  SSL-Session:
      Protocol  : TLSv1.2
      Cipher    : ECDHE-ECDSA-AES256-GCM-SHA384
  ..truncated..
  ```
  find a valid cipher (was _ECDHE-ECDSA-AES256-GCM-SHA384_ with _TLSv1.2_),
  then creating a python SSLContext using this cipher in a
  [sample test script](https://stackoverflow.com/a/26851670),
  with no success

- trying to make python allow weak ciphers and using deprecated SSLv3 by using an SSLContext that allow them:
  ```python
  ~> python3.5
  >>>  import ssl
  >>>  import urllib.request

  >>>  # ssl.get_server_certificate(('postmarketos.org', 443), ssl_version=ssl.PROTOCOL_SSLv23) # => same exception

  >>>  ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  >>>  ctx.options &= ~ssl.OP_ALL
  >>>  ctx.options &= ~ssl.OP_NO_SSLv3 # I know that the server is only avaible with TLSv1.2 but I was desperate ^^'
  >>>  ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
  >>>  # tried also: ctx.set_ciphers('DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK')

  >>>  response = urllib.request.urlopen(url, context=ctx) # => same exception

  >>>  # or even using a customized HTTPSHandler
  >>>  https_handler = urllib.request.HTTPSHandler(context=ctx)
  >>>  url_opener = urllib.request.build_opener(https_handler)
  >>>  url_opener.open(url) # => same exception

  >>>  # also tried to set default ciphers
  >>>  urllib.request.ssl._DEFAULT_CIPHERS = 'ECDHE-ECDSA-AES256-GCM-SHA384'
  >>>  response = urllib.request.urlopen(url, context=ctx) # => same exception
  ```

- updating all my python dependencies and all stuff like _openssl_, _python3-openssl_, _python3-certifi_, _python3-urllib3_, etc.
  a redo all the above tests, with no luck

- doing all that from a different machine with the same python version, with same no results

I had to give up making it work with _python3.5_ !  
When I updated to _python3.7_, everything started working flawlessly with any workground.


### (Not recommended) Patching rss2email to disable SSL verification

In order to avoid failure when RSS feeds are protected with an invalid SSL certificate, you can disable SSL certificate verification by patching an rss2email file.

Open the file :
```
rssbot/lib/python3.7/site-packages/rss2email/feed.py
```
_Replace `python3.7` by your python version._

And add the following lines, after the last import line `from . import util as _util` :
```python
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
