import os
import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class BlogMain(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("blog.html", posts=posts)


class BlogPost(Handler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        self.render("blog.html", post=post)


class NewPost(Handler):
    def get(self):
        self.render("blog-new.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            a = Post(subject=subject, content=content)
            a.put()
            self.redirect("/blog/%s" % a.key().id())
        else:
            error = 'we need both subject and content'
            self.render(
                "blog-new.html", subject=subject,
                content=content, error=error
            )


app = webapp2.WSGIApplication([
    ('/', BlogMain),
    ('/blog', BlogMain),
    ('/blog/', BlogMain),
    ('/blog/newpost', NewPost),
    ('/blog/(\d+)', BlogPost),
], debug=True)
