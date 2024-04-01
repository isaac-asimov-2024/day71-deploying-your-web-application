# imports
from datetime import date, timedelta
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
# this produces error when working with Flask 3.0.0 and above. so I replaced it with a function to produce a Gravatr
# url (see later in code)
# from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Importing all forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
from hashlib import md5
import smtplib
from dotenv import load_dotenv
load_dotenv()

# constants and globals

# for sending an email alert if the contact form was submitted
MY_EMAIL = os.getenv("MY_EMAIL")
MY_PASSWORD = os.getenv("MY_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
GMAIL_SMTP_SERVER = "smtp.gmail.com"

# ------------------------------------ App & DB Initialization & Configuration --------------------------------------- #

# initializing the Flask app
app = Flask(__name__)

# configuring the app's secret key
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# creating a ckeditor object and connecting it to the app
ckeditor = CKEditor(app)

# creating the flask-bootstrap connection
Bootstrap5(app)

# initializing the login manager
login_manager = LoginManager()

# configuring the app for login functionality with the login manager (note: the app must have secret key configured)
login_manager.init_app(app)


# creating the DB model
class Base(DeclarativeBase):
    pass


# creating the db and connecting it to the app
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URI")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Configuring the BlogPost table in the db. it has a child-parent relationship with the User table, and a parent-child
# relationship with the Comment table
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    # A text area field is a good choice when you want to store information from something like a comment box on a
    # form or if you are importing a large block of text.
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    # we define a one-to-many relationship between the User (parent) table and this BlogPost (child) table by placing a
    # foreign key on this child table referencing the parent.
    # in "users.id" the 'users' refers to the tablename of User.
    # the result is that the user's id from the User table is defined as the author_id (= id of the author of the
    # blogpost) in this table
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    # To establish a bidirectional relationship in one-to-many, where the “reverse” side is a many to one, we use the
    # back_populates parameter of the relationship() method. its value in each side (parent / child table) is the
    # attribute name of the relationship() on the other side (child / parent table).
    # the result is that we create a reference to the User object. The "posts" refers to the posts property in the
    # User class.
    # note: the author property of BlogPost is now a User object.
    author = relationship("User", back_populates="posts")
    # # alternative version:
    # author: Mapped["User"] = relationship(back_populates="posts")

    # we establish a bidirectional relationship with the child class, Comment.
    post_comments = relationship("Comment", back_populates="parent_post")


# Configuring the User table in the db for all the registered users. it has a parent-child relationship with the
# Blogpost table, and also with the Comment table.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # To establish a bidirectional relationship in one-to-many, where the “reverse” side is a many to one, we use the
    # back_populates parameter of the relationship() method. its value in each side (parent / child table) is the
    # attribute name of the relationship() on the other side (child / parent table).
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # # alternative version:
    # posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")

    # we establish a bidirectional relationship with the other child class, Comment.
    comments = relationship("Comment", back_populates="comment_author")


# Configuring the Comment table in the db to house comments to the blog posts. it has a child-parent relationship with
# the BlogPost table, and also with the User table.
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    # we define a one-to-many relationship between the User (parent) table and this Comment (child) table by placing a
    # foreign key on this child table referencing the parent.
    comment_author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    # we establish a bidirectional relationship with the parent. the author property of Comment is now a User object.
    comment_author = relationship("User", back_populates="comments")

    # we define another one-to-many relationship between the BlogPost (parent) table and this Comment (child) table.
    parent_post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    # we establish a bidirectional relationship with the parent. the post property of Comment is now a BlogPost object.
    parent_post = relationship("BlogPost", back_populates="post_comments")


# creating all the tables in the db according to the above defined models
with app.app_context():
    db.create_all()


# ------------------------------------- Helper & Decorator Functions ------------------------------------------------- #

# helper function to generate a Gravatar URL (since importing Gravatar, which is usually used to generate the url, from
# flask_gravatar, creates error when working with Flask 3.0.0 and above)
def gravatar_url(email, size=100, rating='g', default='retro', force_default=False):
    """
    Generates a Gravatar URL based on the provided email address and parameters.

    :param email: The email address of the user.
    :param size: The desired size of the Gravatar image (default is 100 pixels).
    :param rating: The content rating for the Gravatar (default is 'g' for general audiences).
    :param default: The default image to display if no Gravatar is found (default is 'retro').
    :param force_default: Whether to force the default image even if a Gravatar exists (default is False).
    :return: The Gravatar URL.
    """

    # creating a hashed value of the email with md5. the .hexdigest() returns the hexadecimal representation of the hash
    hash_value = md5(email.lower().encode('utf-8')).hexdigest()

    # returning a gravatar URL that requests a Gravatar icon with the defined parameters
    return f"https://www.gravatar.com/avatar/{hash_value}?s={size}&d={default}&r={rating}&f={force_default}"


# user loader callback function, used to reload the user object from the user ID stored in the session. It should take
# the str ID of a user, and return the corresponding user object.
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# function activated before every request, used to end the user session after 5 minute inactive.
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)
    session.modified = True


# decorator function to restrict access to certain routes to admin only
def admin_only(function):
    @wraps(function)
    # the (*args, **kwargs) take care of functions that have arguments (such as the edit_post function that receives a
    # post id as argument)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return function(*args, **kwargs)
        else:
            # the flask abort() function sends the required error message by code
            return abort(403)

    return decorated_function


# ------------------------------------------------- Routes ----------------------------------------------------------- #

# route to register a new user
@app.route('/register', methods=["GET", "POST"])
def register():

    # creating the register form
    register_form = RegisterForm()

    # if a registration form was submitted
    if register_form.validate_on_submit():

        # Check if user email is already present in the database.
        user = db.session.execute(db.select(User).where(User.email == register_form.email.data)).scalar()

        # if the user entered an email that already exists in the DB, we redirect him to the login page with a flash
        # message that tells him he already signed up with that email, so he should try to log-in instead
        if user:
            flash("You already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        # otherwise:
        else:
            # hashing the password passed by the user
            hashed_and_salted_password = generate_password_hash(register_form.password.data,
                                                                method="pbkdf2:sha256",
                                                                salt_length=8)

            # creating a new User object (entry) with the data entered by the user, adding it to the db, and logging
            # the user in
            new_user = User(
                email=register_form.email.data,
                password=hashed_and_salted_password,
                name=register_form.name.data,
            )

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            # then redirecting him to the home page to view the posts list
            return redirect(url_for('get_all_posts'))

    # rendering the 'register' template with the register form
    return render_template("register.html", form=register_form)


# route to log in an existing user
@app.route('/login', methods=["GET", "POST"])
def login():

    # creating the login form
    login_form = LoginForm()

    # if the login form was submitted
    if login_form.validate_on_submit():

        # check if the email entered by user exists in db, and if so get the user it belongs to
        user_to_check = db.session.execute(db.select(User).where(User.email == login_form.email.data)).scalar()

        # if the email does not exist in the db, flash a message notifying the user
        if not user_to_check:
            flash("The email entered does not exist in the database. Try again.")

        # if the password entered does not match the user's hashed password, flash a message notifying the user
        elif not check_password_hash(user_to_check.password, login_form.password.data):
            flash("The password entered is incorrect. Try again.")

        # if the email exists in the db and the password that was entered matches the user's stored hashed password,
        # then log-in the user and redirect him to the home page route to view the posts list
        else:
            login_user(user_to_check)
            return redirect(url_for("get_all_posts"))

    # rendering the 'login' template with the login form
    return render_template("login.html", form=login_form)


# route to log out a user
@app.route('/logout')
def logout():
    # logging out the user
    logout_user()

    # redirecting to the home page
    return redirect(url_for('get_all_posts'))


# route to render the home page, where the list of posts' (titles) is shown.
@app.route('/')
def get_all_posts():

    # getting all the post-entries from the db and converting the (single) scalar object to a list of entry objects
    posts = db.session.execute(db.select(BlogPost)).scalars().all()

    # rendering the home page with the list of post-entries
    return render_template("index.html", all_posts=posts)


# route to a single post display page. contains users' comments on the post. logged-in users are allowed to add comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):

    # getting the requested post from the db by its id
    requested_post = db.get_or_404(BlogPost, post_id)

    # creating the comment form
    comment_form = CommentForm()

    # if a comment form was submitted
    if comment_form.validate_on_submit():

        # checking if the user is logged in. if not, redirecting him to the login page with a flash message telling him
        # he needs to log in, in order to leave comments
        if not current_user.is_authenticated:
            flash('You need to log in or register to comment.')
            return redirect(url_for("login"))

        # if the user is logged in, creating a new Comment object with the comment's data, and saving it as an entry in
        # the Comment table in the db
        else:
            # note: we don't need to add the comment_author_id and parent_post_id attributes (they will be filled
            # automatically in the db ,instead of the actual objects, based on the passed objects comment_author and
            # parent_post) (note: the db only needs the id because the tables are related and connected to each other -
            # for example it doesn't need to store the comment_author object in the comment entry, because it can reach
            # the comment author object in the User table by its ID).
            new_comment = Comment(
                body=comment_form.body.data,
                comment_author=current_user,
                parent_post=requested_post
            )

            db.session.add(new_comment)
            db.session.commit()

            # redirecting back to the post page
            return redirect(url_for("show_post", post_id=requested_post.id))

    # rendering the post page with the requested post, the comment form, and the function to produce a gravatar for
    # each user (gravatar_url())
    return render_template("post.html", post=requested_post, form=comment_form, gravatar_url=gravatar_url)


# route to create a new blog post. the "admin_only" decorator ensures that only an admin user can access this route
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():

    # creating the post form
    form = CreatePostForm()

    # if a post form was submitted
    if form.validate_on_submit():

        # creating a new post object and adding it as an entry to the BlogPost table in the db
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()

        # redirecting to the home page
        return redirect(url_for("get_all_posts"))

    # rendering the template to create a new post, with the post form
    return render_template("make-post.html", form=form)


# route to edit an existing blog-post. the "admin_only" decorator ensures that only an admin user can access this route
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):

    # getting the requested post-entry from the db by its ID
    post = db.get_or_404(BlogPost, post_id)

    # creating the 'edit post' form, filled with the existing post details (to be edited by admin user)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    # if an edit form was submitted
    if edit_form.validate_on_submit():

        # updating the new post details in the post-entry in the db
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()

        # redirecting back to the post page
        return redirect(url_for("show_post", post_id=post.id))

    # rendering the template to create a new post or edit an existing post with the 'edit post' form, and a variable
    # indicating that this time it is to be used to edit a post (not create new)
    return render_template("make-post.html", form=edit_form, is_edit=True)


# route to delete an existing blog post. (also deletes associated comments from db). the "admin_only" decorator ensures
# that only an admin user can access this route
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):

    # getting the requested post-entry from the db by its ID
    post_to_delete = db.get_or_404(BlogPost, post_id)

    # getting the post's comment-entries in the db (also need to be deleted)\
    comments_to_delete = db.session.execute(db.select(Comment).where(Comment.parent_post_id == post_id)).scalars().all()

    # deleting the comments first
    for comment in comments_to_delete:
        db.session.delete(comment)

    # deleting the post from db and committing
    db.session.delete(post_to_delete)
    db.session.commit()

    # redirecting to the home page
    return redirect(url_for('get_all_posts'))


# route to the "about" page
@app.route("/about")
def about():
    return render_template("about.html")


# route for the "contact" page
@app.route("/contact", methods=["GET", "POST"])
def contact():

    # if the function receives a 'post' request (meaning the contact form was filled and submitted by a user) it
    # extracts the submitted form-data (using the 'request' method) and sends a notification email with the formatted
    # data to the blog's admin / owner
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        message = request.form["message"]

        formatted_message = f"Name: {name}\nEmail: {email}\nPhone Number: {phone}\nMessage: {message}"
        print(formatted_message)

        try:
            # changed method for sending emails (so it would work on web published blog)
            smtp_server = smtplib.SMTP_SSL(GMAIL_SMTP_SERVER, 465)
            smtp_server.ehlo()
            smtp_server.login(MY_EMAIL, MY_PASSWORD)
            smtp_server.sendmail(from_addr=MY_EMAIL, to_addrs=ADMIN_EMAIL,
                                 msg=f"subject:New Message!\n\n{formatted_message}")
            smtp_server.close()
            print("Email sent successfully!")

        except Exception as ex:
            print("Something went wrong….", ex)

        else:
            # rendering the contact page with a "success" message to notify the user that the form was submitted and
            # handled
            return render_template("contact.html", msg_sent=True)

    # otherwise, if the function receives a 'get' request it renders the contact page with the contact form to fill
    return render_template("contact.html", msg_sent=False)


if __name__ == "__main__":
    app.run(debug=False)
