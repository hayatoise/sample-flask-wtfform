from typing import Text

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user

from application.models import User
from application.database import db
from application.forms.signup import SignupForm

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    # フォームの空欄を確認
    if email == '' or password == '':
        flash('メールアドレスまたはパスワードが空欄です')
        return redirect(url_for('auth.login'))

    # メールアドレスは 6 ~ 254 文字以内
    if not 6 <= len(email) <= 254:
        flash('メールアドレスは 6 ~ 254 文字以内にして下さい')
        return redirect(url_for('auth.login'))

    # パスワードの長さは 12 文字以上
    if not 12 <= len(password):
        flash('パスワードは 12 文字以上にして下さい')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()

    # ユーザ情報の有無を確認
    if not user:
        flash('入力されたメールアドレスが正しくありません')
        return redirect(url_for('auth.login'))

    # パスワードのチェック
    if not check_password_hash(user.password, password):
        flash('入力されたパスワードが正しくありません')
        return redirect(url_for('auth.login'))

    login_user(user, remember=remember)

    return redirect(url_for('main.profile'))


@auth.route('/signup', methods=['GET', 'POST'])
def signup() -> Text:
    signup_form = SignupForm()

    if request.method == 'POST':
        if signup_form.validate_on_submit():
            form = dict(request.form)
            email: str = form.get('email')
            name: str = form.get('name')
            display_name: str = form.get('display_name')
            password: str = form.get('password')
            hashed_password: str = generate_password_hash(password, method='sha256')
            new_user = User(name=name, display_name=display_name, email=email, password=hashed_password)

            try:
                db.session.add(new_user)
                db.session.commit()
            except Exception as e:
                print(e)
                db.session.rollback()
                raise
            finally:
                db.session.close()

            return redirect(url_for('auth.login'))

    return render_template('signup.html', form=signup_form)


@auth.route('/logout')
@login_required
def logout() -> Text:
    logout_user()
    return redirect(url_for('main.index'))
