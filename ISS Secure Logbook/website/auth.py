#session is a flask extension used to support the server-side application for login attempts
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, app
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from datetime import timedelta
    
auth = Blueprint('auth', __name__)

#This is the maximum attempts for password attempts; it can be changed.
max_attempts = 3

@auth.route('/login', methods=['GET', 'POST'])

def login():
    if not session.get('attempt'):
        session['attempt'] = 1
        flash('Setting attempt to 1!', category='success')
    if session['attempt'] > max_attempts:
        return render_template('errorpage.html', user=current_user)
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                session['attempt'] = 1
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
        
            else:
                session['attempt'] = session['attempt'] + 1
                if session['attempt'] > max_attempts:
                    return render_template('errorpage.html', user=current_user)
                else:
                    flash('Incorrect password, try again. ' + str(max_attempts + 1 - session['attempt']) + ' attempts remaining.', category='error')
        else:
            flash('Email does not exist.', category='error')
   
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


SpecialSym =['$', '@', '#', '%']

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

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
            flash ('Password should have at least one uppercase letter', category='error')
        elif not any(char.islower() for char in password1 and password2):
            flash('Password should have at least one lowercase letter', category='error')
        elif not any(char in SpecialSym for char in password1 and password2):
            flash('Password should have at least one of the symbols $@#', category='error') 
        elif len(password1) < 8:
            flash('Password must be at least 8 characters.', category='error')
        
            
      
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
            
    return render_template("sign_up.html", user=current_user)

