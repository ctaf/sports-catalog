from flask import Flask, render_template, url_for, request, redirect, jsonify, flash
from flask import session as login_session
from werkzeug import secure_filename

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, Image
from functools import wraps
import random
import string
import httplib2
import json
import requests
import os
import hashlib
import hmac


IMG_FOLDER = 'static/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)
app.config['IMG_FOLDER'] = IMG_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2.5 * 1024 * 1024  # max 2.5MB


# Helper functions

def purge_session(session, key):
    if session.get(key):
        del session[key]
        return True


def genAppSecretProof(app_secret, access_token):
    h = hmac.new (
        app_secret.encode('utf-8'),
        msg=access_token.encode('utf-8'),
        digestmod=hashlib.sha256
    )
    return h.hexdigest()


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.template_filter('split')
def split_filter(s, sep):
    return s.split(sep)


def require_login(func):
    """
    Redirect to login page if not logged in.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        else:
            return func(*args, **kwargs)

    return wrapper


def whitespace(func):
    """
    Translates whitespaces to underscores in function arguments.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*[a.replace('_', ' ') for a in args],
                    **{k: kwargs[k].replace('_', ' ') for k in kwargs})
    return wrapper


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', state=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        message = "Invalid state parameter."
        return render_template('info.html', message=message)

    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    # print 'exchange url: ', url
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    # strip expire tag from access token
    token = result.split("&")[0]

    appsecret_proof = genAppSecretProof(app_secret, access_token)
    url = 'https://graph.facebook.com/v2.2/me?access_token=%s&appsecret_proof=%s' %\
          (access_token, appsecret_proof)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s" % url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['facebook_id'] = data["id"]
    login_session['email'] = data.get("email")

    # The token must be stored in the login_session in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # h = httplib2.Http()
    # result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s" % url
    # print "API JSON result: %s" % result
    # data = json.loads(result)
    # login_session['picture'] = data["data"]["url"]

    message = "Welcome, %s." % login_session['username']

    return message


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    h.request(url, 'DELETE')[1]
    return "You have been logged out."


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = 'Invalid state parameter.'
        return render_template('info.html', message=response)
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = 'Failed to upgrade the authorization code.'
        return render_template('info.html', message=response)

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = result.get('error')
        return render_template('info.html', message=response)

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = "Token's user ID doesn't match given user ID."
        return render_template('info.html', message=response)

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = "Token's client ID does not match app's."
        return render_template('info.html', message=response)

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        purge_session(login_session, 'credentials')
        return 'Current user is already connected.'

    # Store the access token in the session for later use.
    login_session['gplus_id'] = gplus_id

    # store only the access_token
    login_session['credentials'] = credentials.access_token
    # return credential object
    credentials = AccessTokenCredentials(login_session['credentials'],
                                         'user-agent-value')
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    message = "Welcome, %s." % login_session['username']

    return message


# Disconnect based on provider
# @app.route('/disconnect')
@app.route('/logout')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            purge_session(login_session, 'gplus_id')
            purge_session(login_session, 'credentials')

        elif login_session['provider'] == 'facebook':
            fbdisconnect()
            purge_session(login_session, 'facebook_id')

        purge_session(login_session, 'provider')

    purge_session(login_session, 'username')
    purge_session(login_session, 'email')
    message = 'You have been logged out.'

    return render_template('info.html', message=message)


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        message = "Current user not connected."
        return render_template('info.html', message=message)

    try:
        access_token = credentials.access_token
    except AttributeError:
        message = "No access token provided."
        return render_template('info.html', message=message)

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response =  'Failed to revoke token.'
        return render_template('info.html', message=response)

# @app.route('/gdisconnect')
# def gdisconnect():
#     def reset_user():
#         # Reset the user's sesson.
#         del login_session['credentials']
#         del login_session['gplus_id']
#         del login_session['username']
#         del login_session['email']
#         del login_session['picture']

#     access_token = login_session.get('credentials')
#     if not access_token:
#         message = "Current user not connected."
#         return render_template('info.html', message=message)

#     url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
#     h = httplib2.Http()
#     result = h.request(url, 'GET')[0]
#     reset_user()

#     if result['status'] != '200':
#         print 'Failed to revoke token.'

#     message = 'You have been logged out.'
#     return render_template('info.html', message=message)


@app.route('/')
def mainpage():
    cats = session.query(Category).all()
    app.config['CATEGORIES'] = cats
    it_obj = session.query(Item).\
             order_by(Item.updated_on).limit(10).all()
    it_names = [{'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.category.name}
                for i in it_obj]
    return render_template('main.html', cats=cats, items=it_names)


@app.route('/catalog.json')
def categoryJSON():
    cats = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in cats])


@app.route('/catalog/<string:category_name>/<string:item_name>')
@whitespace
def categoryItem(category_name, item_name):
    item = session.query(Item).join(Category).filter(Category.name ==
            category_name).filter(Item.name == item_name).one()
    return render_template('item.html', item=item)


@app.route('/catalog/<string:category_name>/items')
@whitespace
def category(category_name):
    cats = session.query(Category).all()
    cat = session.query(Category).filter_by(name=category_name).one()
    it_names = ({'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.category.name}
                for i in cat.items)
    return render_template('category.html', cats=cats, items=it_names)


@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
@whitespace
def newItem(category_name):

    # Make sure that the category list has been initialized
    if not app.config.get('CATEGORIES'):
        app.config['CATEGORIES'] = session.query(Category).all()

    category = session.query(Category).filter_by(name=category_name).one()

    if request.method == 'POST':
        imgfile = request.files.get('image')

        if imgfile and allowed_file(imgfile.filename.lower()):
            filename = secure_filename(imgfile.filename)
            imgfile.save(os.path.join(app.config['IMG_FOLDER'], filename))
            image = Image(filename=filename)
            newItem = Item(name=request.form['name'],
                                  description=request.form['description'],
                                  category=category,
                                  image=image)
        else:
            newItem = Item(name=request.form['name'],
                                  description=request.form['description'],
                                  category=category,
                                  image=Image(filename=''))
        session.add(newItem)
        session.commit()
        return redirect(url_for('category', category_name=category.name))
    else:
        return render_template('newitem.html', category_name=category_name)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
@whitespace
def editItem(category_name, item_name):
    editedItem = session.query(Item).join(Category).filter(Category.name ==
            category_name).filter(Item.name == item_name).one()

    if request.method == 'POST':
        imgfile = request.files.get('image')

        if imgfile and allowed_file(imgfile.filename.lower()):
            filename = secure_filename(imgfile.filename)
            imgfile.save(os.path.join(app.config['IMG_FOLDER'], filename))
            editedItem.image = Image(filename=filename)

        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
 	newCategory = session.query(Category).filter_by(name=request.form['category_name']).one()
        editedItem.category_id = newCategory.id
        session.add(editedItem)
        session.commit()

        return redirect(url_for('category',
            category_name=newCategory.name.replace(' ', '_')))

    else:
        return render_template('newitem.html', item=editedItem)


@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
@whitespace
def deleteItem(category_name, item_name):

    deleteItem = session.query(Item).join(Category).filter(Category.name ==
            category_name).filter(Item.name == item_name).one()

    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        return redirect(url_for('category', category_name=category_name))
    else:
        return render_template('deleteitem.html', item=deleteItem)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
