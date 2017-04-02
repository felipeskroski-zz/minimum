import webapp2
from app.views import (
    BlogFront,
    PostPage,
    NewPost,
    EditPost,
    DeletePost,
    LikePost,
    EditComment,
    DeleteComment,
    Register,
    Login,
    Logout,
    Welcome
)

# Routes
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
