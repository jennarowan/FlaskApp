'''
This module builds our forms!
'''

from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,EqualTo

class RegistrationForm(FlaskForm):

    '''
    This is the registration form for new users.
    '''

    username = StringField('username', validators =[DataRequired()])
    password_1 = PasswordField('Password', validators = [DataRequired()])
    password_2 = PasswordField('Confirm Password', validators = \
        [DataRequired(),EqualTo('password_1')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):

    '''
    This is the login form for existing users.
    '''

    username = StringField('Username',validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ResetPasswordForm(FlaskForm):

    '''
    This form allows an existing user to change their password.
    '''

    existing_password = PasswordField('Current Password', validators = \
        [DataRequired()])
    new_password_1 = PasswordField('New Password', validators = \
        [DataRequired()])
    new_password_2 = PasswordField('Confirm New Password', validators = \
        [DataRequired(),EqualTo('new_password_1')])
    submit = SubmitField('Reset Password')
