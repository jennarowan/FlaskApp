'''
Jenna Rowan
SDEV 300
11/29/2022
'''

import re
import os
from datetime import datetime
from forms import RegistrationForm,LoginForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, \
    logout_user, login_required
from passlib.hash import pbkdf2_sha512
from flask import Flask, render_template, url_for, redirect, request, flash

application = Flask(__name__)

@application.before_first_request
def create_tables():
    db.create_all()

# This section of code lets the webpages load new content without
# needing to restart the server
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
    This function renders the guest home page.
    '''

    # # Grabs our guest homepage image to be rendered
    # image_file = url_for('static', filename="loginreq.png")
    # return render_template("index.j2", image_file=image_file, \
    #     datetime = str(datetime.now()))

    # Grabs our homepage image to be rendered
    image_file = url_for('static', filename="liquor.jpg")
    return render_template("home.j2", image_file=image_file, \
        datetime = str(datetime.now()), current_user=current_user)

# @application.route('/home')
# def home():

#     '''
#     This function renders the actual home page after the user
#     has registered or logged in.
#     '''

#     # Grabs our homepage image to be rendered
#     image_file = url_for('static', filename="liquor.jpg")
#     return render_template("home.j2", image_file=image_file, \
#         datetime = str(datetime.now()))

@application.route('/register', methods=['GET', 'POST'])

def register():

    '''
    This function renders the user registration page.
    '''

    # Relevant
    image_file = url_for('static', filename="password_strength.png")

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username =form.username.data, email = form.email.data)
        user.set_password(form.password1.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.j2', form=form, image_file=image_file)

# def register():

#     '''
#     This function renders the user registration page.
#     '''

#     # Relevant
#     image_file = url_for('static', filename="password_strength.png")

#     if request.method == 'GET':

#         return render_template('register.j2', image_file=image_file)

#     error = None

#     if request.method == 'POST':

#         # Grabs the data the user filled in
#         username = request.form['username']
#         password = request.form['password']
#         passwordtwo = request.form['passwordtwo']

#         # Finds common errors, sasses user
#         if not username:

#             error = 'Please enter your Username.'

#         elif not password:

#             error = 'Please enter your Password.'

#         elif not passwordtwo:

#             error = "Both password fields must be filled out."

#         elif password != passwordtwo:

#             error = "Passwords do not match."

#         # Determines if username is taken already with subsidiary function
#         elif not check_not_reg(username):

#             error = 'This username is taken.'

#         # Determines password matches complexity requirements with subsidiary
#         # function
#         else:

#             error = check_complexity(password)

#         # They get to try again
#         if error:

#             return render_template('register.j2', error=error, \
#                 image_file=image_file)

#     # Success

#     # Hash the password
#     password = pbkdf2_sha512.hash(password)

#     # Open credentials file and write the username and password
#     with open('passfile.txt', "a", encoding="utf-8") as file:

#         file.writelines(f"\n{username},{password}")

#     return redirect(url_for('home'))

@application.route('/login', methods=['GET', 'POST'])
def login():

    '''
    This function renders the user login page.
    '''

    # Grabs an image to be rendered that I was reminded of
    # when trying to remember my password
    image_file = url_for('static', filename="i-forgot.jpg")

    # if request.method == 'GET':

    #     return render_template('login.j2', image_file=image_file)

    # if request.method == 'POST':

    #     # Grabs the data the user filled in
    #     username = request.form['username']
    #     password = request.form['password']

    #     # Checks to ensure that the login credentials are valid
    #     # with subsidiary function
    #     error = check_login_valid(username, password)

    #     # They get to try again
    #     if error:

    #         return render_template('login.j2', image_file=image_file, \
    #             error=error)

    # # Success
    # return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            next = request.args.get("next")
            return redirect(next or url_for('home'))
        flash('Invalid email address or Password.')    
    return render_template('login.j2', form=form, image_file=image_file)

def check_login_valid(username, password):

    '''
    This function checks the username and password that
    the user provided (or didn't) against the login
    credentials stored in passfile.txt.

    Errors are returned for any problems, otherwise the
    user is successfully logged in.

    The "for row in f" section was adapted from:
    https://www.itcodar.com/python/
    python-login-script-usernames-and-passwords-in-a-separate-file.html
    '''

    error = None

    while True:

        # Username wasn't even provided
        if not username:

            error = 'Please enter your Username.'
            break

        # Password wasn't even provided
        if not password:

            error = 'Please enter your Password.'
            break

        # Checks to make sure the user exists and, if so,
        # that the password is correct

        # Open credentials file
        with open('passfile.txt', "r", encoding="utf-8") as file:

            for row in file:

                # Breaks each row into two items: username and password
                creds = row.split(",")
                creds_username = creds[0]

                # Username found
                if username == creds_username:

                    creds_password = creds[1].strip()

                    if pbkdf2_sha512.verify(password, creds_password):

                        return error

                    error = "Password is incorrect"
                    return error

            error = "Username not found"
            break

    return error

def check_complexity(password):

    '''
    This function runs when the user tries to register and checks
    that their password is at least 12 characters in length,
    and includes at least 1 uppercase letter, at least 1 lower case
    letter, at least 1 number, and at least 1 special character.
    '''

    error = None

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

def check_not_reg(username):

    '''
    This function checks the credentials file against
    the username that was provided.  If the username
    is found then there is already a registered user
    with that name.
    '''

    # Open credentials file
    with open('passfile.txt', "r", encoding="utf-8") as file:

        for row in file:

            # Breaks each row into two items: username and password
            creds = row.split(",")
            creds_username = creds[0]

            # Username found (already taken)
            if username == creds_username:

                return False

    return True

@login_manager.user_loader
def load_user(user_id):

    '''
    This function is used by the login_manager to
    fetch the current user id.
    '''
    try:
        return User.query.get(int(user_id))
    except:
        return None

@application.route("/forbidden",methods=['GET', 'POST'])
@login_required
def protected():
    return redirect(url_for('forbidden.html'))

class User(db.Model, UserMixin):

    '''
    This class builds objects for registered users with
    a user id, username, email, hashed password, and when
    the user registered.
    '''

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), index=True, unique=True)
    email = db.Column(db.String(150), unique = True, index = True)
    password_hash = db.Column(db.String(150))
    joined_at = db.Column(db.DateTime(), default = datetime.utcnow, \
        index = True)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

    def get(self, id):
        return self.user_id

    def set_password(self, password):
        self.password_hash = pbkdf2_sha512.hash(password)

    def check_password(self,password):
        return pbkdf2_sha512.verify(password, self.password_hash)

    def get(self):
        return id