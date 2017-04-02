import re
import random
import hashlib
import hmac
from string import letters
from config import config

# Regular expressions for validation

# accepts usernames between 3 and 20 characters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
# accepts emails following x@x.x format
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
# accepts passwords between 3 and 20 characters
PASS_RE = re.compile(r"^.{3,20}$")

# creates the salt for security !!change this!! on the config.py file
secret = config['secret']


# ------------------------------------------------
# HELPERS
# ------------------------------------------------

# Validation helpers
def valid_username(username):
    """Checks if username is valid"""
    return username and USER_RE.match(username)


def valid_password(password):
    """Checks if password is valid"""
    return password and PASS_RE.match(password)


def valid_email(email):
    """Checks if email is valid"""
    return not email or EMAIL_RE.match(email)


# Password security helpers
def make_secure_val(val):
    """Creates secure token"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Reads secure token and checks if is valid"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    """Creates random salt"""
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """Creates password hash"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """Checks if password is valid"""
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
