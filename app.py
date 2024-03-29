'''
Jenna Rowan
SDEV 300
12/13/2022
'''

import re
import os
import time
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, \
    logout_user, login_required
from passlib.hash import pbkdf2_sha512
from flask import Flask, render_template, url_for, redirect, request
from forms import RegistrationForm,LoginForm,ResetPasswordForm

application = Flask(__name__)

# Creates the database to hold user information
@application.before_first_request
def create_tables():

    '''
    This function ensures the database is created.
    '''

    db.create_all()

# This section of code lets the webpages load new content without
# needing to restart the server
# It works for the templates, but not for the code in this file
config = {
    "DEBUG": True  # run app in debug mode
}
application.jinja_env.auto_reload = True
application.config['TEMPLATES_AUTO_RELOAD'] = True

# This section (and others) are designed to use a database for user
# registration and login, after I got dinged on Lab 7 because my
# routes were open to non-logged in users.
# Adapted from https://betterprogramming.pub/
# a-detailed-guide-to-user-registration-login-and-logout-in-flask-e86535665c07
# (As well as several other tutorials and Stack Overflow posts I had to turn
# to in order to get this working)

application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(application)
SECRET_KEY = os.urandom(32)
application.config['SECRET_KEY'] = SECRET_KEY
login_manager = LoginManager()
login_manager.init_app(application)

if __name__ == "__main__":

    application.run(debug=True, host='0.0.0.0')

@application.route('/')
def home():

    '''
    This function renders the home page.
    '''

    # Grabs our homepage images to be rendered, based on whether
    # the user is logged in or not
    image_file_logged_in = url_for('static', filename="liquor.jpg")
    image_file_not_logged_in = url_for('static', filename="loginreq.png")

    return render_template("home.j2", \
        image_file_logged_in=image_file_logged_in, \
        image_file_not_logged_in=image_file_not_logged_in, \
        datetime = str(datetime.now()), current_user=current_user)

@application.route('/register', methods=['GET', 'POST'])
def register():

    '''
    This function renders the user registration page.
    '''

    # Relevant
    image_file = url_for('static', filename="password_strength.png")

    form = RegistrationForm()
    error = None

    if form.validate_on_submit():

        while True:

            if form.username.data == "" or \
                form.password_1.data == "" or \
                form.password_2.data == "":

                error = "All fields must be filled out."
                break

            # Checks to ensure username is not taken
            exists = User.query.filter_by(username = \
                form.username.data).first() is not None

            if exists:

                error = "This username is already taken"

            else:

                # Checks validity of password
                error = check_complexity(form.password_1.data)

                if not error:

                    # Grabs the information the user entered
                    user = User(username = form.username.data)
                    user.set_password(form.password_1.data)

                    # Adds it to the database
                    db.session.add(user)
                    db.session.commit()

                    # Logs the user in and returns them to the newly wide open
                    # homepage
                    login_user(user)
                    return redirect(url_for('home'))

            break

    return render_template('register.j2', form=form, image_file=image_file, \
        error=error)

@application.route('/login', methods=['GET', 'POST'])
def login():

    '''
    This function renders the user login page.
    '''

    # Grabs an image to be rendered that I was reminded of
    # when trying to remember my password
    image_file = url_for('static', filename="i-forgot.jpg")
    bad_login_gif = url_for('static', filename="badlogin.gif")

    error = None

    form = LoginForm()

    if form.validate_on_submit():

        while True:

            if form.username.data == "" or \
                form.password.data == "":

                error = "All fields must be filled out."
                break

            user = User.query.filter_by(username = form.username.data).first()

            # Once user enters login info (and it is valid) this returns
            # them to the homepage, with all hidden routes and items
            # now open to them.
            if user is not None and user.check_password(form.password.data):

                login_user(user)
                return redirect(url_for('home'))

            # User failed to provide correct information
            # We log the date, time, and IP address of the user so that
            # potential malicious actors can be traced.
            error = "Invalid username or password."
            log_failed_login()
            break

    return render_template('login.j2', form=form, image_file=image_file, \
        error=error, bad_login_gif=bad_login_gif)

@application.route('/passwordreset', methods=['GET', 'POST'])
def password_reset():

    '''
    This function renders the password reset page.
    '''

    # Grabs an image to be rendered that I was reminded of
    # when trying to remember my password
    image_file = url_for('static', filename="passwordreset.gif")

    error = None

    form = ResetPasswordForm()

    if form.validate_on_submit():

        while True:

            if form.existing_password.data == "" or \
                form.new_password_1 == "" or \
                form.new_password_2 == "":

                error = "All fields must be filled in."
                break

            if form.existing_password.data == form.new_password_1.data:

                error = "New password cannot be the same as old password."
                break

            user = User.query.filter_by(username = \
                current_user.get_username()).first()

            # Checks that user entered the correct password
            # they are currently using
            if user.check_password(form.existing_password.data):

                # Checks proposed new password for adherence
                # to complexity requirements
                error = check_complexity(form.new_password_1.data)

                if not error:

                    # Grabs the information the user entered
                    user.set_password(form.new_password_1.data)

                    # Adds it to the database
                    db.session.commit()

                    return redirect(url_for('home'))

            else:

                error = "Invalid current password"

            break

    return render_template('passwordreset.j2', form=form, \
        image_file=image_file, error=error)

@application.route('/logout')
@login_required
def logout():

    '''
    This function returns the user to the guest home page.
    '''

    logout_user()
    return redirect('/')

@application.route('/liquors')
@login_required
def liquors():

    '''
    This function renders the Liquors list page.
    '''

    return render_template("liquors.j2")

@application.route('/stores')
@login_required
def stores():

    '''
    This function renders the Stores list page.
    '''

    return render_template("stores.j2")

@application.route('/links')
@login_required
def links():

    '''
    This function renders the Useful Links page.
    '''

    return render_template("links.j2")

@login_manager.user_loader
def load_user(user_id):

    '''
    This function is used by the login_manager to
    fetch the current user id.
    '''
    try:

        return User.query.get(int(user_id))

    except ValueError:

        return None

@application.route("/forbidden",methods=['GET', 'POST'])
@login_required
def protected():

    '''
    This function renders a default page when the user
    tries to access a route that they need to be logged
    in for (while they are not logged in.)
    '''

    return redirect(url_for('forbidden.html'))

def check_complexity(password):

    '''
    This function runs when the user tries to register and checks
    that their password is at least 12 characters in length,
    and includes at least 1 uppercase letter, at least 1 lower case
    letter, at least 1 number, and at least 1 special character.
    '''

    error = None

    # Checks the common passwords text file to ensure that the user
    # is not trying to use one of the common passwords.

    # NOTE TO PROFESSOR: It's actually completely impossible for
    # someone to even try using these, because none of the passwords
    # on this list satisfy the existing password requirements:
    # (12+ length, 1+ uppercase, 1+ lowercase, 1+ special char)
    # This check is therefore completely redundant

    with open("CommonPasswords", "r", encoding="utf-8") as file:

        for row in file:

            if row.strip() == password:

                return "This password is one that is commonly used.  Please " \
                    "choose something else."

    # This method of checking for special characters adapted from
    # https://www.knowprogram.com/python/
    # check-special-character-python/

    special_character_list = re.compile(r"[@_!#$%^&*()<>/\|?}{~:]")

    if len(password) < 12:

        error = "Your password needs to be at least 12 characters."

    elif not any(character.isupper() for character in password):

        error = "Your password must contain at least one uppercase letter."

    elif not any(character.islower() for character in password):

        error = "Your password must contain at least one lowercase letter."

    elif not any(character.isdigit() for character in password):

        error = "Your password must contain at least one digit."

    elif special_character_list.search(password) is None:

        error = "Your password must contain at least one special character."

    return error

def log_failed_login():

    '''
    When a user fails to login successfully this function logs
    the date, time, and IP address of the user in the
    loginFails.log file
    '''

    cur_time = time.ctime(time.time())
    ip_addr = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    with open("loginfails.log", "a", encoding="utf-8") as file:

        file.write(f"{cur_time} - Failed login attempt from {ip_addr}\n")

class User(db.Model, UserMixin):

    '''
    This class builds objects for registered users with
    a user id, username, email, hashed password, and when
    the user registered.
    '''

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    password_hash = db.Column(db.String(150))
    joined_at = db.Column(db.DateTime(), default = datetime.utcnow, \
        index = True)
    is_authenticated = True
    is_active = True
    is_anonymous = False

    def get_id(self):

        '''
        This function grabs the user's user_id.
        '''

        return self.user_id

    def get(self):

        '''
        This function grabs the user's user_id.
        '''

        return self.user_id

    def get_username(self):

        '''
        This function grabs the user's username.
        '''

        return self.username

    def set_password(self, password):

        '''
        This function sets the user's password.
        '''
        self.password_hash = pbkdf2_sha512.hash(password)

    def check_password(self,password):

        '''
        This function determines whether the user entered
        a password that matches the hashed one we have on file.
        '''

        return pbkdf2_sha512.verify(password, self.password_hash)
