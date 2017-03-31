import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')


jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True, auto_reload=True)

# creates the salt for security
secret = 'secret-sauce'

# Regular expressions for validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
PASS_RE = re.compile(r"^.{3,20}$")


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """Creates secure token"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    """Reads secure token and checks if is valid"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val





class BlogHandler(webapp2.RequestHandler):
    """Base blog class with useful generic methods"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def get_post_by_id(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        return db.get(key)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
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
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author_id = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.ListProperty(db.Key)

    def is_author(self, user):
        if not user:
            return None
        if str(user.key().id()) == str(self.author_id):
            return True

    def is_liked(self, user):
        if not user:
            return None
        if user.key() in self.likes:
            return True

    def render(self, user=None):
        self._render_text = self.content.replace('\n', '<br>')
        if self.is_liked(user):
            return render_str("post.html", p=self, is_liked=True, user=True)
        if self.is_author(user):
            return render_str("post.html", p=self, is_author=True, user=True)
        return render_str("post.html", p=self, user=False)


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, user=self.user)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", title="New Post")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')
        uid = str(self.user.key().id())
        if subject and content:
            p = Post(subject=subject, content=content, author_id=uid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject,
                content=content, error=error, title="New Post")


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            subject = post.subject
            content = post.content
            if(post.is_author(self.user)):
                self.render(
                    "newpost.html", subject=subject,
                    content=content, title="Edit Post")
            else:
                self.render(
                    "newpost.html", subject=subject,
                    content=content, title="Edit Post",
                    error="Sorry only the author can edit this post")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id))
        p = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')
        if(p.is_author(self.user)):
            if subject and content:
                p.subject = subject
                p.content = content
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "Add subject and content, please!"
                self.render(
                    "newpost.html", subject=subject,
                    content=content, error=error, title="Edit Post")
        else:
            error = "And you're not the author"
            self.render(
                "newpost.html", subject=subject,
                content=content, error=error, title="Edit Post")

class DeletePost(BlogHandler):
    def get(self, post_id):
        p = Post.get_by_id(int(post_id))
        if p.is_author(self.user):
            p.delete()
            self.redirect('/blog')
        else:
            self.redirect('/blog')

class LikePost(BlogHandler):
    def get(self, post_id):
        # if there's no user logged don't like
        if not self.user:
            self.redirect('/blog')
        key = db.Key.from_path('Post', int(post_id))
        p = db.get(key)
        # if user is the author it can't like
        if(p.is_author(self.user)):
            self.redirect('/blog')
        ukey = self.user.key()
        # toggle like on/off
        if ukey in p.likes:
            p.likes.remove(ukey)
            p.put()
        else:
            p.likes.append(ukey)
            p.put()
        self.redirect('/blog')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/signup', Unit2Signup),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
