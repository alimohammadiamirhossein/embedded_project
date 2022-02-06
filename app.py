from flask import Flask
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

app = Flask(__name__)

password = 0


def password_maker():
    x = str(randint(100000, 999999))
    return str.encode(x)


def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key


def make_string_from_password(message, filename):
    private_key = load_key(filename)
    public_key = private_key.public_key()

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


@app.route('/amir')
def public_key():
    global password
    password = password_maker()
    filename1 = 'privkey_amir.pem'
    return make_string_from_password(password, filename1)

@app.route('/hossein')
def public_key(rew):
    string = request.args['string']
    global password
    password = password_maker()
    filename1 = 'privkey_hossein.pem'
    return make_string_from_password(password, filename1)
r.get(url, params={'string':"value"})
if __name__ == '__main__':
    app.run()