import json
import requests
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
#  session is a flask extension used to support the server-side application for login attempts
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, app
from .models import User
# This security library implments secure authication visa hashing and salting.
from . import db
#  Timedelta function to calculate attempts
#from datetime import timedelta

auth = Blueprint('auth', __name__)

# This is the maximum attempts for password attempts; it can be changed.
max_attempts = 3

@auth.route('/login', methods=['GET', 'POST'])


def login():
    """"
    Form login.
    """
    #  These conditions monitor password attempts for 3 tries.
    #  Warnings are flashed on each attempt.
    if not session.get('attempt'):
        session['attempt'] = 1
        flash('Setting attempt to 1!', category='success')
    if session['attempt'] > max_attempts:
        return render_template('errorpage.html', user=current_user)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        captcha_response = request.form.get('g-recaptcha-response')
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                session['attempt'] = 1  #  First attempt matched against hashed password
                if password:
                    if is_human(captcha_response):
                        login_user(user, remember=True)
                        return redirect(url_for('views.home'))
                    else:
                       flash('Bots are not allowed!', category='error')
            else:
                session['attempt'] = session['attempt'] + 1
                #  Third failed attempt sends user to an error page.
                if session['attempt'] > max_attempts:
                    return render_template('login.html', user=current_user)
                else:
                    flash('Incorrect password, try again. ' + str(
                          max_attempts + 1 - session['attempt'])
                          + ' attempts remaining.', category='error')
        else:
            flash('Email does not exist.', category='error')
    return render_template("login.html", user=current_user)

def is_human(captcha_response):
    """
    Form captcha.
    """
    secret = '6Lc0SNshAAAAACsZ5gzxwgIS7lLzggP6muRBBP0D'
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']


@auth.route('/logout')
@login_required
def logout():
    """
    Form the logout
    """
    logout_user()
    return redirect(url_for('auth.login'))

# Special characters for password complexity.
SpecialSym =['$', '@', '#', '%']


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    """
    form sign_up
    """
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        # Below are conditions for satisfying password requirements of length and complexity.
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 3:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif not any(char.isdigit() for char in password1 and password2):
            flash('Password1 should have at least one numeral', category='error')
        elif not any(char.isupper() for char in password1 and password2):
            flash('Password should have at least one uppercase letter', category='error')
        elif not any(char.islower() for char in password1 and password2):
            flash('Password should have at least one lowercase letter', category='error')
        elif not any(char in SpecialSym for char in password1 and password2):
            flash('Password should have at least one of the symbols $@#', category='error')
        elif len(password1) < 8:
            flash('Password must be at least 8 characters.', category='error')
        else:
            #  Once password requirements have been met, the password is added
            #  to database hashed and salted according to sha256 hashing function
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
        return render_template("sign_up.html", user=current_user)
