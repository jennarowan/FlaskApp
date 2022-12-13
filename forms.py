'''
This module builds our forms!
'''

from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import EqualTo

class RegistrationForm(FlaskForm):

    '''
    This is the registration form for new users.
    '''

    username = StringField('username')
    password_1 = PasswordField('Password')
    password_2 = PasswordField('Confirm Password', validators = \
        [EqualTo('password_1')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):

    '''
    This is the login form for existing users.
    '''

    username = StringField('Username')
    password = PasswordField('Password')
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ResetPasswordForm(FlaskForm):

    '''
    This form allows an existing user to change their password.
    '''

    existing_password = PasswordField('Current Password')
    new_password_1 = PasswordField('New Password')
    new_password_2 = PasswordField('Confirm New Password', validators = \
        [EqualTo('new_password_1')])
    submit = SubmitField('Reset Password')
