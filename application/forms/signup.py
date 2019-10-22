from wtforms import Form, StringField, PasswordField
from wtforms.validators import Length, DataRequired, Email, Regexp, ValidationError
from wtforms.fields.html5 import EmailField

from application.models import User


class SignupForm(Form):
    email = EmailField('メールアドレス', [
        DataRequired(message='メールアドレスは必須です'),
        Email(message='メールアドレスが不正です'),
        Length(min=6, max=254, message='メールアドレスの長さが不正です')
    ])

    name = StringField('ユーザ名', [
        DataRequired(message='ユーザ名は必須です'),
        Regexp(regex=r'^[a-zA-Z0-9_]+$', message='ユーザ名は英数字とアンダースコアが使えます'),
        Length(min=2, max=15, message='ユーザ名は 2 ~ 15 文字以内です')
    ])

    display_name = StringField('表示名', [
        DataRequired(message='ユーザ名は必須です'),
        Length(max=50, message='表示名は 50 文字以内です')
    ])

    password = PasswordField('パスワード', [
        DataRequired(message='パスワードは必須です'),
        Length(max=1024, message='パスワードは 1024 文字以内です')
    ])

    def confirm_email_address_duplicate(self):
        user = User.query.filter_by(email=self.email.data).first()
        if user is not None:
            raise ValidationError('このメールアドレスは既に使われています')

    def confirm_name_duplicate(self):
        user = User.query.filter_by(name=self.name.data).first()
        if user is not None:
            raise ValidationError('このユーザ名は既に使われています')
