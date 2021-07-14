from flask import Flask, request, jsonify
import hmac
import hashlib
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretstuff'
app.config['JWT_SECRET_KEY'] = 'supersecretstuff'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
jwt = JWTManager(app)

SALT = '89&19bdAa9e0$a'

db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    task = db.relationship('Tasks', backref='users', lazy=False)


class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(100), nullable=False)
    worker = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)


def authenticate(uname, passw):
    user = Users.query.filter_by(username=uname).first() or None
    print('COMES HERE')
    if user and hmac.compare_digest(user.password.encode('utf-8'), passw.encode('utf-8')):
        return user

    return None


def identity(payload):
    print('COMES HERE')
    u_id = payload['identity']
    return Users.query.filter_by(id=u_id).first()

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = authenticate(username,password)
    # if username != "test" or password != "test":
    if user is None:
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run()