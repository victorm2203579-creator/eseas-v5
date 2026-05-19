import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                ValidationError)
from models import User


def _password_strength(form, field):
    pw = field.data or ''
    if len(pw) < 8:
        raise ValidationError('Password must be at least 8 characters.')
    if not re.search(r'[A-Z]', pw):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not re.search(r'\d', pw):
        raise ValidationError('Password must contain at least one number.')


class RegistrationForm(FlaskForm):
    name = StringField('Full Name',
                       validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email Address',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             validators=[DataRequired(), _password_strength])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password',
                                                         message='Passwords must match.')])
    submit = SubmitField('Create Account')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower().strip()).first():
            raise ValidationError('That email is already registered.')


class LoginForm(FlaskForm):
    email = StringField('Email Address',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class ResetRequestForm(FlaskForm):
    email = StringField('Email Address',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password',
                             validators=[DataRequired(), _password_strength])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(),
                                                 EqualTo('password',
                                                         message='Passwords must match.')])
    submit = SubmitField('Reset Password')


class UpdateProfileForm(FlaskForm):
    name = StringField('Full Name',
                       validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email Address',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Save Changes')

    def __init__(self, original_email, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_email = original_email

    def validate_email(self, field):
        if field.data.lower().strip() != self._original_email.lower():
            if User.query.filter_by(email=field.data.lower().strip()).first():
                raise ValidationError('That email is already in use.')
