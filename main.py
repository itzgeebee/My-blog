# Backend code for my blog site
# import all the required libraries and packages
from functools import wraps
import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
import yagmail
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateUserForm, LoginUserForm, CommentForm
from flask_gravatar import Gravatar



login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    comments = db.relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_author = db.relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    text = db.Column(db.String(500), nullable=False)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = db.relationship("BlogPost", back_populates="comments")



class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="comment_author")


# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1 or not current_user.is_authenticated:
            return abort(403, description="Forbidden! You do not have access to this page")
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():

        new_user = User(email=form.email.data,
                        password=generate_password_hash(form.password.data, method='pbkdf2'
                                                                                   ':sha256',
                                                        salt_length=8),
                        name=form.name.data
                        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            error = "email already exists"
            return redirect(url_for("login", error=error))
        else:

            login_user(new_user)
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = request.args.get("error")
    if error is None:
        error = ""
    form = LoginUserForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        user = User.query.filter_by(email=user_email).first()
        if not user:
            error = "Invalid email"
        else:
            if check_password_hash(pwhash=user.password, password=user_password):
                login_user(user)
                return redirect(url_for("get_all_posts", name=user.name))
            else:
                error = "Invalid password"

    return render_template("login.html", form=form, error=error, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        new_comment = Comment(text=comment_form.comment.data, comment_author=current_user, parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post,
                           logged_in=current_user.is_authenticated, comment_form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    reader_message = ""
    name = request.form.get("mailer")
    mail = request.form.get("mailer-address")
    number = request.form.get("mailer-num")
    message = request.form.get("mailer-msg")
    if request.method == "POST":
        gmail_sender = os.environ.get("gmailsender")
        gmail_pass = os.environ.get("gmail_password")
        gmail_receiver = os.environ.get("gmail_receiver")
        yagmail.register(gmail_sender, gmail_pass)

        receiver = gmail_receiver
        body = f"Sender name:{name}\n Sender mail:{mail}\n Sender number:{number}\n message:{message}"

        yag = yagmail.SMTP(gmail_sender)
        yag.send(
            to=receiver,
            subject="new message from blog",
            contents=body,
        )
        flash("Sent successfully!")
        redirect(url_for("contact"))
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),

        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
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
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>", methods=["GET", "POST"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:comment_id>", methods=["GET", "POST"])
@admin_only
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    post_id = comment_to_delete.blog_id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
