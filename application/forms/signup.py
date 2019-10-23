from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, DataRequired, Email, Regexp, ValidationError
from wtforms.fields.html5 import EmailField

from application.models import User


class SignupForm(FlaskForm):
    email = EmailField('メールアドレス', validators=[
        DataRequired(message='メールアドレスは必須です'),
        Email(message='メールアドレスが不正です'),
        Length(min=6, max=254, message='メールアドレスの長さが不正です'),
    ], render_kw={'type': 'email', 'placeholder': 'example@gmail.com'})

    name = StringField('ユーザ名', validators=[
        DataRequired(message='ユーザ名は必須です'),
        Regexp(regex=r'^[a-zA-Z0-9_]+$', message='ユーザ名は英数字とアンダースコアが使えます'),
        Length(min=2, max=15, message='ユーザ名は 2 ~ 15 文字以内です')
    ], render_kw={'type': 'text', 'placeholder': 'hayato'})

    display_name = StringField('表示名', validators=[
        DataRequired(message='表示名は必須です'),
        Length(max=50, message='表示名は 50 文字以内です')
    ], render_kw={'type': 'text', 'placeholder': '伊勢 隼人'})

    password = PasswordField('パスワード', validators=[
        DataRequired(message='パスワードは必須です'),
        Length(min=12, max=1024, message='パスワードは 12 ~ 1024 文字以内です'),
    ], render_kw={'type': 'password'})

    submit = SubmitField('登録する', render_kw={'class': 'button is-success'})

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('このメールアドレスは既に使われています')

    def validate_name(self, name):
        user = User.query.filter_by(name=name.data).first()
        if user is not None:
            raise ValidationError('このユーザ名は既に使われています')
