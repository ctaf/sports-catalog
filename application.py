import random
import string
import httplib2
import json
import requests
import functools
import os
import hashlib
import hmac

import xml.etree.ElementTree as ET
from werkzeug import secure_filename
from flask_wtf.csrf import CsrfProtect

from flask import Flask, render_template, url_for, request
from flask import redirect, jsonify, make_response
from flask import session as login_session

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, Image


# Keep XSS in mind and limit the file extensions
# Upper case extensions are also accepted
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']


engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)()

app = Flask(__name__)
CsrfProtect(app)
app.config['IMG_FOLDER'] = 'static/'  # folder for image upload
app.config['MAX_CONTENT_LENGTH'] = 2.5 * 1024 * 1024  # max 2.5MB



##### Helper functions #####

def purge_session(session, key):
    """Performs a safe delete on the login-session object."""
    if session.get(key):
        del session[key]
        return True


def genAppSecretProof(app_secret, access_token):
    """Generates a sha256 hash of the access token."""
    h = hmac.new (
        app_secret.encode('utf-8'),
        msg=access_token.encode('utf-8'),
        digestmod=hashlib.sha256
    )
    return h.hexdigest()


def allowed_file(filename):
    """Returns True for allowed image formats."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.template_filter('split')
def split_filter(s, sep):
    """Jinja2 filter to split up URLs."""
    return s.split(sep)


##### Decorators #####

def require_login(func):
    """Redirect to login page if not logged in."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in login_session:
            return redirect('/login')
        else:
            return func(*args, **kwargs)

    return wrapper


# Addresses the issue of whitespace in item and/or category names. As the
# jinja templates convert whitespace to underscores to generate web-friendly
# URLs, the underscores have to be translated again before the database
# queries are performed.

def white2under(func):
    """Translates whitespaces to underscores in function arguments."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*[a.replace('_', ' ') for a in args],
                    **{k: kwargs[k].replace('_', ' ') for k in kwargs})
    return wrapper


##### Views #####


# Main page
@app.route('/')
def mainpage():
    cats = dbsession.query(Category).all()
    app.config['CATEGORIES'] = cats
    it_obj = dbsession.query(Item).\
        order_by(Item.updated_on).limit(10).all()

    it_names = [{'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.category.name}
                for i in it_obj]

    return render_template('main.html', cats=cats, items=it_names)


# Item section
@app.route('/catalog/<string:category_name>/<string:item_name>')
@white2under
def categoryItem(category_name, item_name):
    item = dbsession.query(Item).join(Category)\
        .filter(Category.name == category_name)\
        .filter(Item.name == item_name).one()

    return render_template('item.html', item=item)


# Category section
@app.route('/catalog/<string:category_name>/items')
@white2under
def category(category_name):
    cats = dbsession.query(Category).all()
    cat = dbsession.query(Category).filter_by(name=category_name).one()
    it_names = ({'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.category.name}
                for i in cat.items)

    return render_template('category.html', cats=cats, items=it_names)


##### CRUD functions #####

@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
@white2under
@require_login
def newItem(category_name):

    # Make sure that the category list has been initialized
    if not app.config.get('CATEGORIES'):
        app.config['CATEGORIES'] = dbsession.query(Category).all()

    category = dbsession.query(Category).filter_by(name=category_name).one()

    # Validate the CSRF token from the hidden field in the template
    if request.method == 'POST':
        imgfile = request.files.get('image')

        # Create a new item object from the POST data, together with an
        # associated image object, if a valid image was provided.
        # Use secure_filename() to deal with XSS attacks on the file system.
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

        dbsession.add(newItem)
        dbsession.commit()
        return redirect(url_for('category', category_name=category.name))

    else:
        return render_template('newitem.html',
                               category_name=category_name)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
@white2under
@require_login
def editItem(category_name, item_name):

    editedItem = dbsession.query(Item).join(Category)\
        .filter(Category.name == category_name)\
        .filter(Item.name == item_name).one()

    # Validate the CSRF token from the hidden field in the template
    if request.method == 'POST':
        imgfile = request.files.get('image')

        # Check file upload and exchange image, if appropriate
        if imgfile and allowed_file(imgfile.filename.lower()):
            filename = secure_filename(imgfile.filename)
            imgfile.save(os.path.join(app.config['IMG_FOLDER'], filename))
            editedItem.image = Image(filename=filename)

        # Update other attributes of item as well
        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
        newCategory = dbsession.query(Category)\
            .filter_by(name=request.form['category_name']).one()
        editedItem.category_id = newCategory.id

        dbsession.add(editedItem)
        dbsession.commit()

        # The new name might contain whitespace
        return redirect(url_for('category',
                        category_name=newCategory.name.replace(' ', '_')))

    else:
        return render_template('newitem.html',
                               item=editedItem)


@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
@white2under
@require_login
def deleteItem(category_name, item_name):

    deleteItem = dbsession.query(Item).join(Category)\
        .filter(Category.name == category_name)\
        .filter(Item.name == item_name).one()

    if request.method == 'POST':
        dbsession.delete(deleteItem)
        dbsession.commit()
        return redirect(url_for('category', category_name=category_name))
    else:
        return render_template('deleteitem.html', item=deleteItem)


@app.route('/login')
def showLogin():
    # Generate a CSRF token and store it in the session
    # state = ''.join(random.choice(string.ascii_uppercase + string.digits)
    #                 for x in xrange(32))
    # login_session['state'] = state

    return render_template('login.html')


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


##### Login functions #####

@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' +\
          'grant_type=fb_exchange_token&client_id=%s' % app_id +\
          '&client_secret=%s&fb_exchange_token=%s' % (app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    # strip expire tag from access token
    token = result.split("&")[0]

    appsecret_proof = genAppSecretProof(app_secret, access_token)
    url = 'https://graph.facebook.com/v2.2/me?access_token=%s&appsecret_proof=%s'\
          % (access_token, appsecret_proof)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['facebook_id'] = data["id"]
    login_session['email'] = data.get("email")

    # The token must be stored in the login_session in order to properly logout
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

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
        response = 'Failed to revoke token.'
        return render_template('info.html', message=response)


##### API functions #####

@app.route('/catalog.json')
def catalogJSON():
    cats = dbsession.query(Category).all()
    return jsonify(Categories=[c.serialize for c in cats])


@app.route('/catalog.xml')
def catalogXML():

    root = ET.Element('root')
    cats = dbsession.query(Category).all()

    for cat in cats:
        cat_el = ET.SubElement(root, 'category')
        cat_el.text = cat.name
        for it in cat.items:
            it_el = ET.SubElement(cat_el, 'item')
            ET.SubElement(it_el, 'name').text = it.name
            ET.SubElement(it_el, 'description').text = it.description
            ET.SubElement(it_el, 'updated_on').text = "{:%B %d, %Y}"\
                .format(it.updated_on)
            ET.SubElement(it_el, 'cat_id').text = str(it.category_id)

    response = make_response(ET.tostring(root))
    response.headers["Content-Type"] = "application/xml"

    return response


if __name__ == '__main__':
    app.debug = True
    app.secret_key = '\xf4T%\xa6\x1f\xb5\x19\xd6\xf9;S\xbf' +\
                     '\x1fj\xc1\x97\xbe\xce\xe6\x1e^\x06\x8c\xcd'
    app.run(host='0.0.0.0', port=5000)
