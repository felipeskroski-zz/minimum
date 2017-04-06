import jinja2
import os
from google.appengine.ext import db
from helpers import (
    make_pw_hash,
    valid_pw
)

# maps the template directory
template_dir = os.path.join(os.path.dirname(__file__), '../templates')
# loads jinja2 template system environment
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def render_str(template, **params):
    """Renders templates"""
    t = jinja_env.get_template(template)
    return t.render(params)


def users_key(group='default'):
    """Group key for users"""
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    """Group key for posts and comments"""
    return db.Key.from_path('blogs', name)


class User(db.Model):
    """User model with name, email and password"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """Gets user by id"""
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """Gets user by name"""
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """Registers a new user"""
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        """Logs in a new user"""
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# Post Model
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

    def get_author(self):
        """Gets the author of the comment"""
        author = User.by_id(int(self.author_id))
        return author.name

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
    """Comment model"""
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
