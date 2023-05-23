from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
import os
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,validators
from wtforms.validators import DataRequired,Email
from flask_ckeditor import CKEditorField


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
 #Added this line fixed the issue.
login_manager.init_app(app)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = db.relationship('BlogPost', backref='user', cascade='all, delete, delete-orphan')
    comments = db.relationship('Comment', backref='user', cascade='all, delete, delete-orphan')
    def check_password(self, password):
        return check_password_hash(self.password, password)
    def __repr__(self):
        return '<User %r>' % self.name
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),validators.Email()])
    password = StringField("Password", validators=[DataRequired()])
    name = StringField("Your Name", validators=[DataRequired()])
    submit = SubmitField("Register")
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(),validators.Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")
class CommentForm(FlaskForm):
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("comment")
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=['POST','GET'])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        name = form.name.data
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        newuser = User(email=email, password=password, name=name)
        newuser.authenticated = True
        db.session.add(newuser)
        db.session.commit()
        login_user(newuser, remember=True)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login',methods=['POST','GET'])
def login():
    error=None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if user.check_password(form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
                return redirect(url_for('get_all_posts'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'
    return render_template("login.html",error=error,form=form)

@app.route('/logout')
def logout():
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['POST','GET'])
def show_post(post_id):
    form = CommentForm()
    comments = Comment.query.all()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        comment = Comment(
        author = current_user.name,
        text = form.body.data)
        current_user.comments.append(comment)
        db.session.add(comment)
        db.session.commit()
    return render_template("post.html", post=requested_post,form=form,comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['POST','GET'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y")
        )
        current_user.posts.append(new_post)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)
