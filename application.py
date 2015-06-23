import httplib2
import json
import requests
import functools
import os

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

from helpers import purge_session, show_info, generate_signature, allowed_file
from database_setup import Base, Category, Item, Image


# Connect to the database and start a session.
# check_same_thread is necessary for debugging, as the Werkzeug debugger makes
# use of multithreading
engine = create_engine('sqlite:///catalogitems.db?check_same_thread=False')
Base.metadata.bind = engine
dbsession = sessionmaker(bind=engine)()

# Start and configure the app. CSRF protection is enabled for all views, i.e.
# the existence of a valid CSRF token is automatically checked whenever a POST
# request is made.
app = Flask(__name__)
CsrfProtect(app)
app.config['IMG_FOLDER'] = 'static/'  # folder for image upload
app.config['MAX_CONTENT_LENGTH'] = 2.5 * 1024 * 1024  # max 2.5MB
app.config['CATEGORIES'] = dbsession.query(Category).all()


##### Decorators #####

@app.template_filter('split')
def split_filter(s, sep):
    """Jinja2 filter to split up URLs."""
    return s.split(sep)


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

# All CRUD functions use the require_login decorator. Otherwise, you could just
# edit the content by entering the correct URL (which is of course also
# possible when the editing buttons are not visible).

@app.route('/catalog/<string:category_name>/edit', methods=['GET', 'POST'])
@white2under
@require_login
def newItem(category_name):

    # Validate the CSRF token from the hidden field in the template
    if request.method == 'POST':

        # Retrieve the item-related data from request
        imgfile = request.files.get('image')
        name = request.form['name']
        description = request.form['description']
        category_name = request.form['category_name']
        category = dbsession.query(Category)\
            .filter_by(name=category_name).one()

        # At least a name should be provided
        if name:
            # Create a new item object from the POST data, together with an
            # associated image object, if a valid image was provided.
            # Use secure_filename() to deal with XSS attacks on the file system
            if imgfile and allowed_file(imgfile.filename.lower()):
                filename = secure_filename(imgfile.filename)
                imgfile.save(os.path.join(app.config['IMG_FOLDER'], filename))
                image = Image(filename=filename)
                newItem = Item(name=name,
                               description=description,
                               category=category,
                               image=image)
            else:
                newItem = Item(name=name,
                               description=description,
                               category=category,
                               image=Image(filename=''))

            dbsession.add(newItem)
            dbsession.commit()
            return redirect(url_for('category', category_name=category_name))

        else:
            return show_info('Error: Please provide a name for the item.')

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
            editedItem.image.delete_file
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
        return render_template('edititem.html',
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
        deleteItem.image.delete_file
        dbsession.delete(deleteItem)
        dbsession.commit()
        return redirect(url_for('category', category_name=category_name))
    else:
        return render_template('deleteitem.html', item=deleteItem)


@app.route('/login')
def showLogin():
    # All views are CSRF-protected via Flask-WTF, so there is no need to
    # generate and validate a csrf token by hand.
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
    return show_info('You have been logged out.')


##### Login functions #####

@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    # Receive the access_token and use it for requests to the Facebook graph.
    access_token = request.data
    app_data = json.loads(open('fb_client_secrets.json', 'r').read())['web']
    app_id, app_secret = app_data['app_id'], app_data['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' +\
          'grant_type=fb_exchange_token&client_id=%s' % app_id +\
          '&client_secret=%s&fb_exchange_token=%s' % (app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Strip the expire tag from token, then use it to get the user info.
    token = result.split("&")[0]
    appsecret_proof = generate_signature(app_secret, access_token)
    url = 'https://graph.facebook.com/v2.2/me?access_token=%s&appsecret_proof=%s'\
          % (access_token, appsecret_proof)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Store the user info in the session object.
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['facebook_id'] = data["id"]
    login_session['email'] = data.get("email")

    # Also store the token in order to properly logout later on.
    login_session['access_token'] = token.split("=")[1]
    message = "Welcome, %s." % login_session['username']

    return message


@app.route('/fbdisconnect')
def fbdisconnect():
    # Revoke the permissions previously granted to the app
    facebook_id = login_session['facebook_id']
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    httplib2.Http().request(url, 'DELETE')[1]

    return "You have been logged out."


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Obtain the authorization code.
    code = request.data

    # Try to upgrade the authorization code into a credentials object.
    try:
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        return show_info('Failed to upgrade the authorization code.')

    # Check that the access token is valid.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % credentials.access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return show_info(result.get('error'))

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return show_info("Token's user ID doesn't match given user ID.")

    # Verify that the access token is valid for this app.
    app_id = json.loads(open('g_client_secrets.json', 'r')
                        .read())['web']['client_id']
    if result['issued_to'] != app_id:
        return show_info("Token's client ID does not match app's.")

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        purge_session(login_session, 'credentials')
        return show_info("Current user is already connected.")

    # Store the access token in the session for later use.
    login_session['gplus_id'] = gplus_id
    login_session['credentials'] = credentials.access_token
    credentials = AccessTokenCredentials(login_session['credentials'],
                                         'user-agent-value')
    # Get the user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    # Store the user info
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
        return show_info("Current user not connected.")

    try:
        access_token = credentials.access_token
    except AttributeError:
        return show_info("Error: No access token provided.")

    # Revoke the permissions previously granted to the app
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # For whatever reason, the given token was invalid.
    if result['status'] != '200':
        return show_info('Error: Failed to revoke token.')


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
