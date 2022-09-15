# 1. Background
-------------------------------------------------------------
## 1.1 Assignment brief

This project aims to desing a secure application that helps ESA astronnauts on the International Space station to record sensitive research information inline with OWASP'S main security threats (OWASP, 2021) as outlined in our Design document (Ashmore et al, 2022).


--------------------------------------------------------------

## 1.2 Architecture
The ISS Logbook application is built as a web microservice using Flask 2.2.2. The core application was taken from GitHub (TechwithTim2020), and adapted with mutliple security features.

-----------

## 1.3 Threats

In the design document, a few threats were identified applicable to the logbook. These threats included taking over an existing user’s account and upgrading a lesser privileged account to one with more privileges.
For this reason, a program was written in Python (Downey, 2012), which enforces strong password practices, applies cryptographic hashing functions to protect this privileged data, locks the user accounts after too many incorrect login attempts, and separates user data from the more privileged staff data. The password must contain special characters, numbers and upper-case letters. The code will also require users to confirm their password to help them catch any typos. Passwords which meet all the requirements will then be hashed using the SHA-256 cryptographic hashing method and stored in the csv file together with the user’s email address, registration date and the number of login attempts (set to 3 by default for new users) mitigating brute-force attacks. To log in to the logbook, the users will have to enter their email address and password. The entered password will be hashed and compared to the one in the database. If the passwords match, the user will be allowed to login.

## Implementation

Installation:<br>
`bash
git clone <repo-url>
`

Open your terminal:<br>
`bash
pip install -r requirements.txt
`

Run in terminal:<br>
`bash
python main.py
`

Click to view in browser:<br>
`http://127.0.0.1:5000`


------------------------------------------------------------


# 2 Logbook Username, Password, Notes database

-------------------------------------------------------------

# 3 Dependencies

The main modules:

```
Python 3.10.6
Flask 2.2.2
Werkzeug 2.2.2
Sqlalchemy 1.4.41
Sqlite3 3.39.2
```
For a full list of library dependencies:

`pip install -r requirements.txt`

-----------------------------------------------------------

# 4 Authentication Module
------------------------------------------------------------

## 4.1 Registration

## 4.2 Login

## 4.3 Notes

---------------------------------------------------------------
# 5 Security Functions

## 5.1 Password Validation for signup

Password validation should have many paramaters which included complexity, length, history, expiration date, and hashing to ensure account security (Simplilearn.com, 2021). A user creating a password must adhere to the these parameters or the account cannot be created The password must contain at least one whitespace. Futhermore, The password length must be between 8 and 64 characters, and passwords with white spaces tend to be more secure (InfosecMatter, 2021). Below are examples taken from the Logbook app. 

1.`if user:
            flash('Email already exists.', category='error')`
            ![email exists](https://github.com/JonnyAsh/ISS-Logbook/blob/cad72aaad684b9f4fa6cbe8a218c557a0ff28a11/ISS%20Secure%20Logbook/website/images/email%20exists%20already.png)<br><br/>  
            
            
2.`elif len(email) < 10:
            flash('Email must be greater than 10 characters.', category='error')`
![email len](https://github.com/JonnyAsh/ISS-Logbook/blob/7b7553cdd6981c21fb849315b82e619ae368fd8b/ISS%20Secure%20Logbook/website/images/email%20length.png)<br> <br/>

3. `elif len(first_name) < 3:
            flash('First name must be greater than 1 character.', category='error')`
            ![name greater than 1](https://github.com/JonnyAsh/ISS-Logbook/blob/ab61e5a1cbed5773442007ffb9b2709811e60ef2/ISS%20Secure%20Logbook/website/images/first%20name%20len.png)<br><br/>
4. `elif password1 != password2:
            flash('Passwords don\'t match.', category='error')`
            ![password dont math](https://github.com/JonnyAsh/ISS-Logbook/blob/afeeb2392abe52e3dbee8535c33efaa2dcef9885/ISS%20Secure%20Logbook/website/images/not%20match%20password.png)<br><br/>
5. `elif not any(char.isdigit() for char in password1 and password2):
            flash('Password1 should have at least one numeral', category='error')`
           ![roman numeral](https://github.com/JonnyAsh/ISS-Logbook/blob/1018849cb847f14312ca84e071449e6edab1cc1d/ISS%20Secure%20Logbook/website/images/one%20roman%20numeral.png)<br><br/>
            
6. `elif not any(char.isupper() for char in password1 and password2):
            flash ('Password should have at least one uppercase letter', category='error')'`
            ![upper](https://github.com/JonnyAsh/ISS-Logbook/blob/8d8116b70ab20a24a392a58528370470f5e03fd4/ISS%20Secure%20Logbook/website/images/uppercase.png)<br><br/>
7. `elif not any(char.islower() for char in password1 and password2):
            flash('Password should have at least one lowercase letter', category='error')`
            ![lower](https://github.com/JonnyAsh/ISS-Logbook/blob/8d8116b70ab20a24a392a58528370470f5e03fd4/ISS%20Secure%20Logbook/website/images/lowercase.png)<br><br/>
8. `elif not any(char in SpecialSym for char in password1 and password2):
            flash('Password should have at least one of the symbols $@#', category='error')`
            ![symbol](https://github.com/JonnyAsh/ISS-Logbook/blob/a8e696ae2ca9295b103387f4c6265b1bade1c87c/ISS%20Secure%20Logbook/website/images/symbol.png)<br><br/>
            
## 5.2 Password validation for login
One method to increase security is to have a lock-out policy of 3 attempts resulting in a 1-minute lock-out.


```
__init__.py
    # session lifetime set to 1 minute; not IP specific
    @app.before_request
    def make_session_permanent():
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=1)
        session.modified = True
        

auth.py
def login():
    # These conditions monitor password attempts for 3 tries. 
    # Warnings are flashed on each attempt.
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
                session['attempt'] = 1 # First attempt matched against hashed password.
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
        
            else:
                session['attempt'] = session['attempt'] + 1
                if session['attempt'] > max_attempts: # Third failed attempt sends user to an error page.
                    return render_template('login.html', user=current_user)
                else:
                    flash('Incorrect password, try again. ' + str(max_attempts + 1 - session['attempt']) + ' attempts remaining.', category='error')
        else:
            flash('Email does not exist.', category='error')
   
    return render_template("login.html", user=current_user


```


## 5.3 Multifactor Authentication

## 5.4 Captcha
As a mitigation to OWASP top 10 identification and authentication failures, the use of Captcha was introduced. 
1. deter hackers from abusing the app
2. block robot software from submitting fake or nefarious online requests.
3. Protect the integrity of the app by stopping hackers from using robots to send in repeated false responses
4. Prevent fake registrations or sign-ups for websites
5. https://blog.growmarkentum.com/pros-and-cons-using-captcha

Below is the short demonstration from the Logbook app. This was made active by introducing the site key and secret key from google captcha. See below the code section covering the captcha from auth.py

 auth.py

            if user: 
                if check_password_hash(user.password, password): 
                   session['attempt'] = 1 # First attempt matched against hashed password. 
                   if password:
                      if is_human(captcha_response): 
                           login_user(user, remember=True) 
                           return redirect(url_for('views.home')) 
                      else: 
                        flash('Bots are not allowed!', category= 'error')

          def is_human(captcha_response): 
                  secret = '6Lc0SNshAAAAACsZ5gzxwgIS7lLzggP6muRBBP0D' 
                  payload = {'response':captcha_response, 'secret':secret} 
                  response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload) 
                  response_text = json.loads(response.text) 
                  return response_text['success']

![image](https://user-images.githubusercontent.com/94033113/190440541-b520358e-169e-4283-b2e1-501b04da67a3.png)


An example showing how it works.

![image](https://user-images.githubusercontent.com/94033113/190441293-06af4a42-8fae-42a0-9b98-711fad341f64.png)


An example showing the user trying to log in without enabling the captcha.

![image](https://user-images.githubusercontent.com/94033113/190441129-22ceb40b-dea0-42c2-923b-65eaae510f24.png)


## 5.5 Password Hash and salt
The Werkzeug dependency has a security module `werkzeug.security` that generates and checks a password hash for the database. It goes further by adding a salt string length of 8 to the hashing process. The 256-bit hashing function the program uses allows up to 64 hexadecimal characters (Khan, 2021). Salting the hashed password mitigates rainbow attacks (Techmonger, 2022).

An example of a hashed and salted password of a new user:

![hashed password](https://github.com/JonnyAsh/ISS-Logbook/blob/e1522dd1fdad4fb911248224da8844a0f244d38e/ISS%20Secure%20Logbook/website/images/user%20example.png)<br> <br/>
-------------------------------------------------------------

# 6 Linters
Linting referes to tools that can be dowloaded to analyse source code for bugs, stylistics erros, and programming errors. Below are four types: pylint and 
flake8 examine stylistic errors, mccabe searches for complexity, and Bandit analyses for security vulnerabilities.

## 6.1 Flake8
Flake8 is wrapper that checks source code for PEP8 stardard violations; thus, preventing bad formatting and styling (GitHub, 2022).

Install Flake8:
`pip install flake8`

Run Flake8:
`flake8 auth.py`

## 6.2 Pylint
Smiliar to Flake8, this Python module looks for code smells, lists errors, and recommendation corrections (Rjmolyneaux, 2022).

Install mccabe:
`pip install pylint`<br>

Run mccabe:
`python -m pylint auth.py`

## 6.3 McCabe (Cyclomatic Complexity)
This tool measures the number of decisions such as 'if' conditionals in the source code; for example, the lower count, the less complex it is.
Any result between 1 and 10 is considered manageable and clean code (Qac, 2022).

Install Mccabe:
`pip install mccabe`

Run Mccabe:
`python -m mccabe auth.py`

## 6.4 Bandit

Bandit is security analysis tool for scanning source code in Python. It will produce a report based any vulnerabilities such as plain text passwords in the code. Ngetich (2021). 

Install Bandit:
`pip install bandit`<br>

Run Bandit: 
`bandit -r auth.py`<br>

-------------------------------------------------------------

# 7 Testing

------------------------------------------------------------
# 8 Limitations
 
 ----------------------------------------------------------------

# 9 References

Ashmore, J. Adelakun, A. Tolofari, S. (2022) 'Development Team Project: Design Document'. Paper submitted to the university of the University of Essex Online for Secure Software Development Module.

Downey, A.B. (2012) Python for software design how to think like a computer scientist. Cambridge: Cambridge University Press.   (Samuel entry)

GitHub. (2022) PyCQA/flake8. Available from: https://github.com/pycqa/flake8 [Accessed 13 Sep. 2022].
‌

Khan, M.W. (2021) Pool Map With Multiple Arguments in Python. Delft Stack. Available from: https://www.delftstack.com/howto/python/python-pool-map-multiple-arguments/ [Accessed 9 Sep. 2022].   (Samuel entry)

Rjmolyneaux (2022) Use PyLint for Python code - Visual Studio (Windows). docs.microsoft.com. Available from: https://docs.microsoft.com/en-us/visualstudio/python/linting-python-code?view=vs-2022 [Accessed 13 Sep. 2022].
‌

Simplilearn.com. (2021) Understanding Why is the Password Validation Process Important in JavaScript | Simplilearn. Available from: https://www.simplilearn.com/tutorials/javascript-tutorial/password-validation#:~:text=Whenever%20a%20user%20creates%20a%20password%2C%20one%20extra [Accessed 5 Sep. 2022].

Techmonger (2022) Secure Passwords in Python With Werkzeug - Tech Monger. Available from: https://techmonger.github.io/4/secure-passwords-werkzeug/ [Accessed 13 Sep. 2022].
‌
Techmonger (2022) How to add ReCaptcha to Flask App without Extension - Tech Monger. Available from: https://techmonger.github.io/5/python-flask-recaptcha/ [Accessed 9 Sept 2022].

TechwithTim (2020) GitHub - techwithtim/Flask-Web-App-Tutorial: Code for the note storing flask web app made during a YouTube video. GitHub. Available from: https://github.com/techwithtim/Flask-Web-App-Tutorial [Accessed 9 Aug. 2022].

Thangavelu, S. Purusothaman, T. & Gowrison, G. (2014) Analysis of Captcha Security Methods in Web Applications. Available from http://ijcttjournal.org/Volume9/number-8/IJCTT-V9P175.pdf [Accessed 14 Sept 2022] ‌ Qac, H. (2022) Cyclomatic Complexity Explained | Perforce. Available from: https://www.perforce.com/video-tutorials/qac/cyclomatic-complexity-explained#:~:text=Code%20with%20a%20cyclomatic%20complexity%20between%201%20and [Accessed 12 Sep. 2022].

Qac, H. (2022) Cyclomatic Complexity Explained | Perforce. Available from: https://www.perforce.com/video-tutorials/qac/cyclomatic-complexity-explained#:~:text=Code%20with%20a%20cyclomatic%20complexity%20between%201%20and [Accessed 12 Sep. 2022].

Ngetich, A. (2021) How to scan Python Code for Vulnerabilities using Bandit. HacWare Resources. Available from: https://resources.hacware.com/bandit-security-scan-for-python-code/ [Accessed 12 Sep. 2022].
‌
‌
OWASP (2021) OWASP Top 10:2021. owasp.org. Available from: https://owasp.org/Top10/ [Accessed 3 Sept. 2022].



