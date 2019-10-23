from flask import Blueprint, render_template, make_response, Response
from flask_login import current_user

main = Blueprint('main', __name__)


@main.route('/')
def index() -> Response:
    return make_response(render_template('index.html'))


@main.route('/profile')
def profile() -> Response:
    return make_response(render_template('profile.html', name=current_user.name))
