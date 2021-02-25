from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_login.utils import login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, current_user
from flask_bcrypt import Bcrypt
import requests

app = Flask(__name__)
app.secret_key = "The carbuncle ate itself"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column('id',db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    consent = db.Column(db.Boolean)

    def __init__(self, username, password, consent):
        self.username = username
        self.password = password
        self.consent = consent

@login_manager.user_loader
def load_user(userID):
    return(User.query.get(int(userID)))


@app.route('/')
def home():
    return render_template('home.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    # if current_user.is_authenticated:
    #     return redirect(url_for('cookies', info=request.cookies.get('session')))
    if request.method == 'POST':
        user = request.form.get('username')
        pword = request.form.get('password')
        session['user'] = user
        dbUser = User.query.filter_by(username=user).first()
        if dbUser and bcrypt.check_password_hash(dbUser.password, pword):
            session['consent'] = dbUser.consent
            login_user(dbUser)
            flash('You are now logged in!!!', 'info')
            if dbUser.consent:
                return redirect(url_for('memes'))
            else:
                return redirect(url_for('cookies', info=request.cookies.get('session')))
        else:
            flash('Incorrect username/password, please try again.', 'warning')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if 'user' in session:
        session.pop('consent', None)
        session.pop('user', None)
        logout_user()
        flash('You are logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/memes')
@login_required
def memes():
    memeList = []
    for i in range(5):
        memeList.append(requests.get('https://meme-api.herokuapp.com/gimme').json()['url'])
    return render_template('memes.html', memes=memeList)

@app.route('/unset')
def unset():
    user = User.query.filter_by(username=session['user']).first()
    user.consent = False
    db.session.commit()
    return redirect(url_for('login'))

@app.route('/cookies', methods=['GET', 'POST'])
@login_required
def cookies():
    if request.method == 'POST':
        if 'checkbox' in request.form:
            acceptCookies = True
            user = User.query.filter_by(username=session['user']).first()
            user.consent = acceptCookies
            db.session.commit()
            return redirect(url_for('memes'))
        else:
            acceptCookies = False
            logout_user()
            flash('Sorry but we need cookies :(', 'warning')
            return redirect(url_for('login'))
        pass
    else:
        if 'consent' in session and session['consent']:
            flash('Enjoy your memes!', 'info')
            return redirect(url_for('memes'))
        elif 'consent' in session and not session['consent']:
            return render_template('cookies.html', info=request.cookies.get('session'))
        else:
            flash('Session expired!', 'warning')
            return redirect(url_for('login'))

if(__name__ == '__main__'):
    db.create_all()
    app.run(debug=True)