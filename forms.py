# imports
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# WTForm to register new users
class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    # PasswordField makes sure the password is hidden when the user is typing it in
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6)])
    name = StringField(label='Name', validators=[DataRequired()])
    submit = SubmitField(label="Sign Me Up!")


# WTForm to login existing users
class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired(), Email()])
    # PasswordField makes sure the password is hidden when the user is typing it in
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField(label="Let Me In!")


# WTForm to enable users to leave comments below posts
class CommentForm(FlaskForm):
    body = CKEditorField(label='Comment', validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")

