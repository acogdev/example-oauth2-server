# coding: utf-8

from datetime import datetime
from datetime import timedelta
from flask import Flask
from flask import Response
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import render_template_string
from flask import request
from flask import session
from flask import url_for
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import current_user as ldap_current_user
# from flask_login import login_required
from flask_oauthlib.provider import OAuth2Provider
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import JSONWebSignatureSerializer
from werkzeug.security import gen_salt
from flask_ldap3_login.forms import LDAPLoginForm
from flask_login import login_user


app = Flask(__name__, template_folder='templates')

app.secret_key = '4222722111573574'
app.config.update({
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})
db = SQLAlchemy(app)
oauth = OAuth2Provider(app)


# Hostname of your LDAP Server
app.config['LDAP_HOST'] = '10.2.30.166'

# Base DN of your directory
app.config['LDAP_BASE_DN'] = 'dc=ldap,dc=test'

# Users DN to be prepended to the Base DN
app.config['LDAP_USER_DN'] = 'ou=users'

# Groups DN to be prepended to the Base DN
app.config['LDAP_GROUP_DN'] = 'ou=groups'

# The RDN attribute for your user schema on LDAP
app.config['LDAP_USER_RDN_ATTR'] = 'cn'

# The Attribute you want users to authenticate to LDAP with.
app.config['LDAP_USER_LOGIN_ATTR'] = 'mail'

# The Username to bind to LDAP with
app.config['LDAP_BIND_USER_DN'] = None

# The Password to bind to LDAP with
app.config['LDAP_BIND_USER_PASSWORD'] = None

login_manager = LoginManager(app)              # Setup a Flask-Login Manager
ldap_manager = LDAP3LoginManager(app)          # Setup a LDAP3 Login Manager.


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    dn = db.Column(db.Text())
    data = db.Column(db.Text())
    memberships = db.Column(db.Text())


class Client(db.Model):
    client_id = db.Column(db.String(40), primary_key=True)
    client_secret = db.Column(db.String(55), nullable=False)

    user_id = db.Column(db.ForeignKey('user.id'))
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []


class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE')
    )
    user = db.relationship('User')

    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class hiddenUser(object):

    def __init__(self, username, id):
        self.username = username
        self.id = id


def current_user():
    if 'id' in session:
        return User.query.filter_by(username=session['id']).first()
    return None


@app.route('/', methods=('GET', 'POST'))
def home():
    if not ldap_current_user or ldap_current_user.is_anonymous:
        return redirect('http://localhost:5000/login')
    return render_template('home.html', user=current_user())


@app.route('/client/')
def client():
    # TODO: This needs to go from creation to retrieval; I think
    # if not ldap_current_user or ldap_current_user.is_anonymous:
    #     return redirect('http://localhost:5000/login')
    user = current_user()

    if not user:
        return redirect('/')
    item = Client(
        client_id=gen_salt(40),
        client_secret=gen_salt(50),
        _redirect_uris=' '.join(
            ['http://localhost:8000/authorized',
             'http://127.0.0.1:8000/authorized',
             'http://127.0.1:8000/authorized',
             'http://127.1:8000/authorized',
             ]),
        _default_scopes='email',
        user_id=user.id,
    )
    db.session.add(item)
    db.session.commit()
    return jsonify(
        client_id=item.client_id,
        client_secret=item.client_secret,
    )


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    # TODO: Token/grant expire is set to 10 seconds, the original example was
    #       set to expire after 100 seconds
    expires = datetime.utcnow() + timedelta(seconds=10)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user(),  # TODO this user parameter needs to be a DB object
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    # TODO This was using expires_in instead of 10
    expires = datetime.utcnow() + timedelta(seconds=10)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    db.session.add(tok)
    db.session.commit()
    return tok


@app.route('/oauth/token', methods=['GET', 'POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/oauth/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = Client.query.filter_by(client_id=client_id).first()
        kwargs['client'] = client
        kwargs['user'] = user
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return True if confirm == 'yes' else False


@app.route('/oauth/errors')
def errors():
    return 'ERROR: ' + request.args.get('error')


@app.route('/api/me')
@oauth.require_oauth()
def me():
    user = request.oauth.user
    return jsonify(username=user.username)


class ProtectedUser(UserMixin):

    def __init__(self, username, dn, data):
        self.id = username
        self.dn = dn
        self.data = data

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

    @classmethod
    def get(cls, username):
        user = User.query.filter_by(username=username).first()
        return (user.username, user.password)


# @login_manager.request_loader
# def load_user(request):
#     token = request.headers.get('Authorization')
#     if token is None:
#         token = request.args.get('token')

#     if token is not None:
#         jws = JSONWebSignatureSerializer(app.config["SECRET_KEY"])
#         cred = jws.loads(token)

#         username = cred['username']
#         password = cred['password']
#         user_entry = ProtectedUser.get(username)
#         if (user_entry is not None):
#             user = ProtectedUser(user_entry[0], user_entry[1])
#             if (user.password == password):
#                 return user
#     return None


# from flask import session
# from wtforms.csrf.session import SessionCSRF

# class MyBaseForm(LDAPLoginForm):
#     class Meta:
#         csrf = True
#         csrf_class = SessionCSRF
#         csrf_secret = b"app.config['CSRF_SECRET_KEY']"

#         @property
#         def csrf_context(self):
#             return session


# Declare a User Loader for Flask-Login.
# Simply returns the User if it exists in our 'database', otherwise
# returns None.
@login_manager.user_loader
def load_user(id):
    usr = User.query.filter_by(dn=id).first()
    return ProtectedUser(usr.username, usr.dn, usr.data)
    # if id in users:
    #     return users[id]
    # return None


# Declare The User Saver for Flask-Ldap3-Login
# This method is called whenever a LDAPLoginForm() successfully validates.
# Here you have to save the user, and return it so it can be used in the
# login controller.
@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    user = ProtectedUser(username, dn, data)
    usr = User(username=username, dn=dn, data=str(data), memberships=str(memberships))

    session['id'] = usr.username

    if usr.username == User.query.filter_by(dn=dn).first().username:
        return user

    db.session.add(usr)
    db.session.commit()

    return user


@app.route('/login', methods=['GET', 'POST'])
def login():
    template = """
    {{ get_flashed_messages() }}
    {{ form.errors }}
    <form method="POST">
        <label>Username{{ form.username() }}</label>
        <label>Password{{ form.password() }}</label>
        {{ form.submit() }}
    </form>
    """

    # Instantiate a LDAPLoginForm which has a validator to check if the user
    # exists in LDAP.
    form = LDAPLoginForm(csrf_enabled=False)

    if form.validate_on_submit():
        # Successfully logged in, We can now access the saved user object
        # via form.user.
        login_user(form.user)  # Tell flask-login to log them in.
        return redirect('/')  # Send them home

    return render_template_string(template, form=form)


@app.route("/protected/", methods=["GET"])
def protected():
    if not ldap_current_user or ldap_current_user.is_anonymous:
        return redirect('http://localhost:5000/login')
    return Response(response="Hello Protected World!", status=200)


# @app.route('/token', methods=('GET', 'POST'))
# def token():
#     if request.method == 'GET':
#         return render_template('token.html')
#     else:
#         jws = JSONWebSignatureSerializer(app.config["SECRET_KEY"])
#         user = request.form.get('username')
#         password = request.form.get('password')
#         token = jws.dumps({'username': user, 'password': password})
#         return token


if __name__ == '__main__':
    db.create_all()
    app.debug = True
    app.run()
