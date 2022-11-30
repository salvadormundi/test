from functools import wraps
from sqlalchemy.exc import IntegrityError
from flask import Flask, flash, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = "alumni"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(30), unique=True)
    institution = db.Column(db.String(40))


class Admin(db.Model, UserMixin):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(30), unique=True)
    stu_id = db.Column(db.Integer, db.ForeignKey("student.id"))
    stu = db.relationship("Student")


class Student(db.Model):
    __tablename__ = "student"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))
    email = db.Column(db.String(50), unique=True)


def create_app():

    app = Flask(__name__, template_folder="templates", static_folder='static')
    app.config['SECRET_KEY'] = "admin123"
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", 'sqlite:///database.db') 
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
    return app

app = create_app()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=4, max=30)])
    remember = BooleanField("remember me")


class RegistrationForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=40)])
    password = StringField("password", validators=[InputRequired(), Length(min=4, max=30)])
    email = StringField("email", validators=[InputRequired(), Email(message="Invalid Email")])
    institution = StringField("institution", validators=[InputRequired(), Length(min=10, max=40)])


class AdminLoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=4, max=30)])
    remember = BooleanField("remember me")


class AdminRegistrationForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=40)])
    password = StringField("password", validators=[InputRequired(), Length(min=4, max=30)])
    email = StringField("email", validators=[InputRequired(), Email(message="Invalid Email")])

class StudentDetailForm(FlaskForm):
    name = StringField("name", validators=[InputRequired(), Length(min=4, max=40)])
    email = StringField("email", validators=[InputRequired(), Email(message="Invalid Email")])


@app.route("/")
def index():
    return render_template("index.html")



# admin auth

@app.route("/adminlogin", methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()

    if form.validate_on_submit():
        admin = Admin.query.filter_by(username=form.username.data).first()
        if admin and check_password_hash(admin.password, form.password.data):
            login_user(admin, remember=form.remember.data)
            return redirect(url_for('dash'))
        else:
            flash('Invalid Admin Credentials')
            return render_template("admin_login.html", form=form)
    return render_template('admin_login.html', form=form)


@app.route("/adminsignup", methods=['GET', 'POST'])
def admin_signup():
    form = AdminRegistrationForm()

    if form.validate_on_submit():
        hashed_pass = generate_password_hash(form.password.data, method='sha256')

        new_admin = Admin(
            username=form.username.data, 
            email=form.email.data, 
            password=hashed_pass)
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin registered")
        except IntegrityError:
            flash("Admin already registered")
            db.session.rollback()
    
    
    return render_template('admin_signup.html', form=form)


@app.route("/add_student")
@login_required
def add_stu():
    form = StudentDetailForm()

    if form.validate_on_submit():
        new_stu = Student(
            name=form.name.data,
            email = form.email.data
        )
        try:
            db.session.add(new_stu)
            db.session.commit()
            flash("Student added")
        except IntegrityError:
            flash("Each student should have different email")
            db.session.rollback()

    return render_template('add_student.html', name = current_user.username)



@app.route("/list_student")
@login_required
def list_stu():
    students = Student.query.all()

    return render_template('add_student.html', students=students)



# alumni auth

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dash'))
        else:
            flash('Invalid User Credentials')
            return render_template("log-in.html", form=form)
    return render_template('log-in.html', form=form)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_pass = generate_password_hash(form.password.data, method='sha256')

        new_student = User(
            username=form.username.data, 
            email=form.email.data, 
            password=hashed_pass,
            institution=form.institution.data)
        
        try:
            db.session.add(new_student)
            db.session.commit()
            flash("Thank you for registering")
            # return render_template('sign-up.html', form=RegistrationForm())
        except IntegrityError:
            flash("User already registered")
            db.session.rollback()
    
    
    return render_template('sign-up.html', form=form)

@app.route("/dashboard")
@login_required
def dash():
    return render_template('dashboard.html', name = current_user.username)


@app.route("/logout")
@login_required
def logout():
    flash("You have been logged out")
    logout_user()
    return redirect(url_for('index'))



if __name__ == "__main__":
    app.run(debug=True)