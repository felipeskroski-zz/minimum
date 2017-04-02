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

# creates the salt for security !change this!
secret = 'secret-sauce'

# Regular expressions for validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
PASS_RE = re.compile(r"^.{3,20}$")

# ------------------------------------------------
# HELPERS
# ------------------------------------------------
def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


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

# ------------------------------------------------
# MODELS
# ------------------------------------------------
def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """User model with key functions"""
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


# Post Model
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """Blog post model"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author_id = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # likes store a list of users who liked the post
    likes = db.ListProperty(db.Key)

    @classmethod
    def by_id(cls, pid):
        """Get post by id"""
        post = Post.get_by_id(int(pid), parent=blog_key())
        if not post:
            self.error(404)
            return
        return post

    def is_author(self, user):
        """Checks if the user is the author of the post"""
        if not user:
            return None
        if str(user.key().id()) == str(self.author_id):
            return True
        else:
            return False

    def is_liked(self, user):
        """Checks if the post has been liked by the user"""
        if not user:
            return None
        if user.key() in self.likes:
            return True

    def get_comments(self):
        """Get comments from a post"""
        pid = self.key().id()
        comments = Comment.all().filter("post_id =", str(pid))
        return comments

    def render(self, user=None, error=None):
        """Renders the post"""
        self._render_text = self.content.replace('\n', '<br>')
        if self.is_author(user):
            return render_str(
                "post.html", p=self, is_author=True,
                is_logged=True, error=error)

        if self.is_liked(user):
            return render_str(
                "post.html", p=self,
                is_liked=True, is_logged=True, error=error)
        if user:
            return render_str(
                "post.html", p=self, is_logged=True, error=error)
        return render_str("post.html", p=self)

# Comment model
class Comment(db.Model):
    """Comment model """
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author_id = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, cid):
        """Get comment by id"""
        comment = Comment.get_by_id(int(cid), parent=blog_key())
        return comment

    def is_author(self, user):
        """Checks if the user is the author of the comment"""
        if not user:
            return None
        if str(user.key().id()) == str(self.author_id):
            return True
        else:
            return False

    def get_author(self):
        """Gets the author of the comment"""
        author = User.by_id(int(self.author_id))
        return author.name

    def render(self, user=None, error=None):
        """Renders the comment"""
        author = self.get_author()
        return render_str(
            "comment.html", c=self,
            author=author, is_author=self.is_author(user))


# ------------------------------------------------
# CONTROLLERS
# ------------------------------------------------

class Base(webapp2.RequestHandler):
    """Base blog class with useful generic methods"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

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


class BlogFront(Base):
    """All posts page"""
    def get(self):
        # Ancestor query adds strong consistency support to make sure
        # the data is the latest
        posts = Post.all().ancestor(blog_key()).order('-created')
        self.render('front.html', posts=posts, user=self.user)


class PostPage(Base):
    """Single post page"""
    def get(self, post_id):
        post = Post.by_id(int(post_id))
        comments = post.get_comments()
        self.render("permalink.html", post=post,
                    user=self.user, comments=comments)

    def post(self, post_id):
        """Creates a new comment from the post """
        if not self.user:
            self.redirect('/'+post_id)
        content = self.request.get('content')
        uid = str(self.user.key().id())
        p = Post.by_id(int(post_id))
        if content:
            c = Comment(parent=blog_key(), content=content,
                        author_id=uid, post_id=post_id)
            c.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "permalink.html",
                content=content, error=error, user=self.user)


class NewPost(Base):
    """Creates a new post"""
    def get(self):
        # allowed to logged users only
        if self.user:
            self.render("newpost.html", title="New Post")
        # if not logged send to login
        else:
            self.redirect("/login")

    def post(self):
        # if not logged send to home
        if not self.user:
            self.redirect('/')
        # get form fields
        subject = self.request.get('subject')
        content = self.request.get('content')
        # get user id
        uid = str(self.user.key().id())
        if subject and content:
            p = Post(
                parent=blog_key(), subject=subject,
                content=content, author_id=uid)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject,
                content=content, error=error, title="New Post")


class EditPost(Base):
    def get(self, post_id):
        if self.user:
            post = Post.by_id(int(post_id))
            if not post:
                self.redirect("/")
            subject = post.subject
            content = post.content
            if(post.is_author(self.user)):
                self.render(
                    "newpost.html", subject=subject,
                    content=content, title="Edit Post")
            else:
                error = "Sorry only the author can edit this post"
                comments = post.get_comments()
                self.render(
                    "permalink.html", post=post, error=error,
                    user=self.user, comments=comments)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/')
        post = Post.by_id(int(post_id))
        subject = self.request.get('subject')
        content = self.request.get('content')
        if(post.is_author(self.user)):
            if subject and content:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/post/%s' % str(post.key().id()))
            else:
                error = "Add subject and content, please!"
                self.render(
                    "newpost.html", subject=subject,
                    content=content, error=error, title="Edit Post")
        else:
            error = "And you're not the author"
            self.redirect('/')


class DeletePost(Base):
    def get(self, post_id):
        post = Post.by_id(int(post_id))
        if post.is_author(self.user):
            post.delete()
            self.redirect('/')
        else:
            error = "Only the author can delete the post"
            comments = post.get_comments()
            self.render(
                "permalink.html", post=post, error=error,
                user=self.user, comments=comments)


class LikePost(Base):
    def get(self, post_id):
        # if there's no user logged send back to home
        if not self.user:
            self.redirect('/')
        post = Post.by_id(int(post_id))
        # if user is the author it can't like
        if(post.is_author(self.user)):
            error = "The author can't like its own post"
            self.render("permalink.html", post=post,
                        error=error, user=self.user)
            return
        ukey = self.user.key()
        # toggle like on/off
        if ukey in post.likes:
            post.likes.remove(ukey)
            post.put()
        else:
            post.likes.append(ukey)
            post.put()
        self.redirect('/')


# Comments
class EditComment(Base):
    def get(self, c_id):
        if not self.user:
            self.redirect('/login')
            return
        c = Comment.by_id(int(c_id))
        if not c:
            self.redirect('/')
            return
        is_author = c.is_author(self.user)
        if is_author:
            self.render("edit-comment.html", comment=c)
        else:
            post = Post.by_id(int(c.post_id))
            comments = post.get_comments()
            error = "Only the author can edit the comment"
            self.render("permalink.html", post=post, error=error,
                        user=self.user, comments=comments)

    def post(self, c_id):
        if not self.user:
            self.redirect('/'+post_id)
        content = self.request.get('content')
        c = Comment.by_id(int(c_id))
        if content:
            c.content = content
            c.put()
            self.redirect('/post/%s' % str(c.post_id))
        else:
            error = "Content, please!"
            self.render("edit-comment.html", comment=c, error=error)


class DeleteComment(Base):
    def get(self, c_id):
        c = Comment.by_id(int(c_id))
        post_id = c.post_id
        if c.is_author(self.user):
            c.delete()
            self.redirect('/post/%s' % str(post_id))
        else:
            post = Post.by_id(int(c.post_id))
            comments = post.get_comments()
            error = "Only the author can delete the comment"
            self.render("permalink.html", post=post, error=error,
                        user=self.user, comments=comments)

# authentication
class Signup(Base):
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
            self.redirect('/welcome')


class Login(Base):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(Base):
    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(Base):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


app = webapp2.WSGIApplication([
                               ('/?', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/post/new', NewPost),
                               ('/post/edit/([0-9]+)', EditPost),
                               ('/post/like/([0-9]+)', LikePost),
                               ('/post/delete/([0-9]+)', DeletePost),
                               ('/comment/edit/([0-9]+)', EditComment),
                               ('/comment/delete/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ],
                              debug=True)
