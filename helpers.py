import hashlib
import hmac
from flask import render_template

# Keep XSS in mind and limit the file extensions
# Upper case extensions are also accepted
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])


##### Helper functions #####

def purge_session(session, key):
    """Performs a safe delete on the login-session object."""
    if session.get(key):
        del session[key]
        return True


def show_info(message):
    return render_template('info.html', message=message)


def generate_signature(secret, token):
    """Generates a sha256 hash of the access token."""
    return hmac.new(
        secret.encode('utf-8'),
        msg=token.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()


def allowed_file(filename):
    """Returns True for allowed image formats."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
