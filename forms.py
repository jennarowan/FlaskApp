from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired,EqualTo

class RegistrationForm(FlaskForm):

    username = StringField('username', validators =[DataRequired()])
    password1 = PasswordField('Password', validators = [DataRequired()])
    password2 = PasswordField('Confirm Password', validators = \
        [DataRequired(),EqualTo('password1')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):

    username = StringField('Username',validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')