from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from wtforms.fields.html5 import EmailField

from application.models import User


class LoginForm(FlaskForm):
    email = EmailField('メールアドレス', validators=[
        DataRequired(message='メールアドレスは必須です'),
        Email(message='メールアドレスが不正です'),
        Length(min=6, max=254, message='メールアドレスの長さが不正です'),
    ], render_kw={'type': 'email', 'placeholder': 'example@gmail.com'})

    password = PasswordField('パスワード', validators=[
        DataRequired(message='パスワードは必須です'),
        Length(min=12, max=1024, message='パスワードは 12 ~ 1024 文字以内です'),
    ], render_kw={'type': 'password'})

    remember = BooleanField('パスワードを保存する', render_kw={'type': 'checkbox'})

    submit = SubmitField('ログイン', render_kw={'class': 'button is-success'})

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('入力されたメールアドレスが正しくありません')
