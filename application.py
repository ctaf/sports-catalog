from flask import Flask, render_template, url_for, request, redirect, jsonify, flash
from flask import session as login_session
from flask import make_response

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from oauth2client.client import AccessTokenCredentials

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, CatalogItem
from functools import wraps
import random
import string
import httplib2
import json
import requests


app = Flask(__name__)

engine = create_engine('sqlite:///catalogitems.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open(
    'client_secrets.json', 'r').read())['web']['client_id']


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

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['gplus_id'] = gplus_id

    # store only the access_token
    login_session['credentials'] = credentials.access_token
    # return credential object
    credentials = AccessTokenCredentials(login_session['credentials'], 'user-agent-value')

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = login_session['username']
    flash("Welcome, %s" % login_session['username'], 'login')
    print "done!"
    return output


@app.route('/logout')
def logout():
    def reset_user():
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

    access_token = login_session.get('credentials')
    if not access_token:
        # response = make_response(
        #     json.dumps('Current user not connected.'), 401)
        # response.headers['Content-Type'] = 'application/json'
        # return response
        return render_template('logout.html',
                               message="Current user not connected")

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        reset_user()
        # response = make_response(json.dumps('Successfully disconnected.'), 200)
        # response.headers['Content-Type'] = 'application/json'
        response = 'Successfully disconnected.'
    else:
        # For whatever reason, the given token was invalid.
        reset_user()
        # response = make_response(
        #     json.dumps('Failed to revoke token for given user.', 400))
        # response.headers['Content-Type'] = 'application/json'
        response = 'Failed to revoke token for given user.'

    # return response
    return render_template('logout.html', message=response)


@app.route('/')
def mainpage():
    cats = session.query(Catalog).all()
    it_obj = session.query(CatalogItem).\
             order_by(CatalogItem.updated_on).limit(10).all()
    it_names = ({'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.catalog.name}
                for i in it_obj)
    return render_template('main.html', cats=cats, items=it_names)


@app.route('/catalog.json')
def catalogJSON():
    items = session.query(CatalogItem).all()
    return jsonify(CatalogItems=[i.serialize for i in items])


@app.route('/catalog/<string:catalog_name>/<string:item_name>')
@whitespace
@require_login
def catalogItem(catalog_name, item_name):
    item = session.query(CatalogItem).join(Catalog).filter(Catalog.name ==
            catalog_name).filter(CatalogItem.name == item_name).one()
    return render_template('item.html', item=item)


@app.route('/catalog/<string:catalog_name>/items')
@whitespace
def catalog(catalog_name):
    cats = session.query(Catalog).all()
    cat = session.query(Catalog).filter_by(name=catalog_name).one()
    it_names = ({'name': i.name, 'desc': i.description,
                 'fname': i.image.filename, 'cat': i.catalog.name}
                for i in cat.items)
    return render_template('catalog.html', cats=cats, items=it_names)


# @app.route('/catalogs/<int:catalog_id>/new', methods=['GET', 'POST'])
# def newCatalogItem(catalog_id):

# 	if request.method == 'POST':
# 		newItem = CatalogItem(name=request.form['name'], description=request.form[
# 			'description'], price=request.form['price'], course=request.form['course'], catalog_id=catalog_id)
# 		session.add(newItem)
# 		session.commit()
# 		flash("new menu item created!")
# 		return redirect(url_for('catalogMenu', catalog_id=catalog_id))
# 	else:
# 		return render_template('newmenuitem.html', catalog_id=catalog_id)


# @app.route('/catalogs/<int:catalog_id>/<int:menu_id>/edit',
#            methods=['GET', 'POST'])
# def editCatalogItem(catalog_id, menu_id):
#     editedItem = session.query(CatalogItem).filter_by(id=menu_id).one()
#     if request.method == 'POST':
# 		if request.form['name']:
# 			editedItem.name = request.form['name']
# 		session.add(editedItem)
# 		session.commit()
# 		flash("menu item edited!")
# 		return redirect(url_for('catalogMenu', catalog_id=catalog_id))
#     else:
#         return render_template(
#             'editmenuitem.html', catalog_id=catalog_id, menu_id=menu_id, item=editedItem)


# @app.route('/catalog/<int:catalog_id>/<int:menu_id>/delete/',
#            methods=['GET', 'POST'])
# def deleteCatalogItem(catalog_id, menu_id):

# 	deleteItem = session.query(CatalogItem).filter_by(id=menu_id).one()
# 	if request.method == 'POST':
# 		session.delete(deleteItem)
# 		session.commit()
# 		flash("menu item deleted!")
# 		return redirect(url_for('catalogMenu', catalog_id=catalog_id))
# 	else:
# 		return render_template('deletemenuitem.html', catalog_id=catalog_id, item=deleteItem)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
