import os
import jinja2
import webapp2
import re
import random
import hmac
import hashlib
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True
)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

SECRET = 'sauce'


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    key = h.split('|')[0]
    hashs = h.split('|')[1]
    if hash_str(key) == hashs:
        return key


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', 'user_id=%s; Path=/' % cookie_val
        )

    def read_cookie(self):
        cookie_val = self.request.cookies.get('user_id')
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_user_by_name(self, name):
        return User.all().filter('name =', name).get()

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie()
        self.user = uid and User.get_by_id(int(uid))


class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        entered_username = self.request.get('username')
        entered_password = self.request.get('password')
        entered_verify = self.request.get('verify')
        entered_email = self.request.get('email')
        isUser = self.get_user_by_name(entered_username)
        errors = {'username': '', 'password': '', 'verify': '', 'email': ''}
        valid_form = True

        if not USER_RE.match(entered_username):
            errors['username'] = "That's not a valid username"
            valid_form = False

        if not PASS_RE.match(entered_password):
            errors['password'] = "That's not a valid password"
            valid_form = False

        if not entered_verify == entered_password:
            errors['verify'] = "You passwords don't match"
            valid_form = False

        if not EMAIL_RE.match(entered_email) and entered_email:
            errors['email'] = "That's not a valid email"
            valid_form = False

        if isUser:
            errors['username'] = "That user already exists."
            valid_form = False

        if not valid_form:
            self.render(
                "signup.html", errors=errors,
                username=entered_username, email=entered_email
            )
        else:
            u = User(
                name=entered_username, password=hash_str(entered_password),
                email=entered_email
            )
            u.put()
            user_id = u.key().id()
            self.set_cookie(str(user_id))
            self.redirect("/signup/welcome")


class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = self.get_user_by_name(username)
        errors = {'username': '', 'password': ''}
        if not user:
            errors['username'] = "User or password not valid"
            self.render("login.html", errors=errors, username=username)
        else:
            if user.password == hash_str(password):
                user_id = user.key().id()
                self.set_cookie(str(user_id))
                self.redirect("/signup/welcome")
            else:
                errors['username'] = "User or password not valid"
                self.render("login.html", errors=errors, username=username)


app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/signup/', Signup),
    ('/signup/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
], debug=True)
