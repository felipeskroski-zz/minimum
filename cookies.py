import os
import jinja2
import webapp2
import hashlib
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)
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

def make_salt():
    length = 5
    return ''.join(random.choice(string.lowercase) for i in range(length))

def make_pw_hash(name, pw):
    s = make_salt()
    h = hashlib.sha256(name + pw + s).hexdigest()
    return "%s,%s" % (h,s)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    if h == make_pw_hash(name, pw, salt):
        return True

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Main(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_val = self.request.cookies.get('visits')
        if visit_cookie_val:
            cookie_val = check_secure_val(visit_cookie_val)
            if cookie_val:
                visits = int(cookie_val)

        visits += 1

        new_cookie_val = make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)


        if visits > 10:
            self.write("you're awesome")
        else:
            self.write("You've been here %s times" % visits)

app = webapp2.WSGIApplication([
    ('/cookies', Main),
], debug=True)
