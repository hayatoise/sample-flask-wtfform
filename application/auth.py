from flask import Blueprint, render_template, redirect, url_for, request, flash, make_response, Response
from flask_login import login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

from application.database import db
from application.models import User
from application.forms.login import LoginForm
from application.forms.signup import SignupForm

auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login() -> Response:
    login_form = LoginForm()

    if request.method == 'POST':
        if login_form.validate_on_submit():
            dict_type_form = dict(request.form)
            email: str = dict_type_form.get('email')
            password: str = dict_type_form.get('password')
            remember: bool = True if dict_type_form.get('remember') else False
            user = User.query.filter_by(email=email).first()
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user, remember=remember)
                return make_response(redirect(url_for('main.profile')))
            elif not check_password_hash(pwhash=user.password, password=password):
                flash('入力されたパスワードが正しくありません')
                return make_response(redirect(url_for('auth.login')))
            else:
                flash('予期せぬエラーが発生しました')
                return make_response(redirect(url_for('auth.login')))

    return make_response(render_template('login.html', form=login_form))


@auth.route('/signup', methods=['GET', 'POST'])
def signup() -> Response:
    signup_form = SignupForm()

    if request.method == 'POST':
        if signup_form.validate_on_submit():
            dict_type_form = dict(request.form)
            email: str = dict_type_form.get('email')
            name: str = dict_type_form.get('name')
            display_name: str = dict_type_form.get('display_name')
            password: str = dict_type_form.get('password')
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

            return make_response(redirect(url_for('auth.login')))

    return make_response(render_template('signup.html', form=signup_form))


@auth.route('/logout')
@login_required
def logout() -> Response:
    logout_user()
    return make_response(redirect(url_for('main.index')))
