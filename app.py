from flask import Flask, request, jsonify
from flask.cli import with_appcontext

import hashlib
import datetime
import click
import os

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import sql

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


# NOTE:- request.json (instead of request.form) is used in post requests. Please write json body in postman for post requests to work 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretstuff'
app.config['JWT_SECRET_KEY'] = 'supersecretstuff'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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


@click.command('create-tables')
@with_appcontext
def create_tables():
    db.create_all()
    print('Tables Created')

app.cli.add_command(create_tables)

def authenticate(uname, passw):
    user = Users.query.filter_by(username=uname).first() or None
    print('COMES HERE')
    if user and user.password == passw:
        return user
    return None

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username", None)
    password = hashlib.md5(request.json.get("password", None).encode()).hexdigest()
    user = authenticate(username,password)
    # if username != "test" or password != "test":
    if user is None:
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route('/signup-admin', methods=['POST'])
def signup_admin():
    username = request.json.get("username", None)
    password = hashlib.md5(request.json.get("password", None).encode()).hexdigest()
    role = 'admin'
    u = Users(username=username, password=password, role=role)
    db.session.add(u)
    db.session.commit()
    return 'Admin added !'


@app.route('/signup-worker', methods=['POST'])
def signup_worker():
    username = request.json.get("username", None)
    password = hashlib.md5(request.json.get("password", None).encode()).hexdigest()
    role = 'worker'
    u = Users(username=username, password=password, role=role)
    db.session.add(u)
    db.session.commit()
    return 'User added !'


@app.route('/users')
@jwt_required()
def users():
    current_user = Users.query.filter_by(username=get_jwt_identity()).first() or None
    if current_user.role != 'admin': return 'You are not allowed to do this action'
    j = {}
    for i in Users.query.all():
        j[i.username] = {
            'role': i.role,
            'tasks': len(i.task)
        }
    
    return jsonify(j)


@app.route('/jobs', methods=['GET', 'POST'])
@jwt_required()
def jobs():
    if request.method == 'GET':
        current_user = Users.query.filter_by(username=get_jwt_identity()).first() or None
        if current_user.role == 'admin':
            worker =  Users.query.filter_by(username=request.args.get('worker')).first() or None 
        else:
            worker = current_user
        user = worker # Users.query.filter_by(username=worker).first() or None
        j = {}
        if user:
            for i in user.task:
                j[i.task] = i.status
            return jsonify(j)
        elif user is None:
            return 'No such user'

    elif request.method == 'POST':
        worker  = request.json.get('worker_name') # worker name is used instead of worker id
        task = request.json.get('task')
        status = request.json.get('status')

        user =  Users.query.filter_by(username=worker).first() or None
        if user:
            t = Tasks(task=task, status=status)
            user.task.append(t)
            db.session.add(user)
            db.session.commit()

            return 'Task added successfully !'
        elif user is None:
            return 'No such worker'


@app.route('/update-job', methods=['POST'])
@jwt_required()
def update_job():
    current_user = Users.query.filter_by(username=get_jwt_identity()).first() or None
    if current_user.role == 'admin':
        worker = Users.query.filter_by(username=request.json.get('worker')).first() or None
        print(worker)
    else:
        worker = current_user
    user = worker       

    if user is None: return 'No such worker'

    task = request.json.get('task')
    status = request.json.get('status')
    task = Tasks.query.filter_by(task=task, worker=user.id).first() or None

    if task is None: return 'No such task'

    task.status = status

    db.session.add(task)
    db.session.commit()

    return 'Task updated'



@app.route('/delete-job', methods=['POST'])
@jwt_required()
def delete_job():
    current_user = Users.query.filter_by(username=get_jwt_identity()).first() or None
    if current_user.role != 'admin': return 'You are not allowed to do this action'
    worker = Users.query.filter_by(username=request.json.get('worker')).first() or None

    if worker is None: return 'No such worker'

    task = request.json.get('task')
    task = Tasks.query.filter_by(task=task, worker=worker.id).first() or None

    if task is None: return 'No such task'


    db.session.delete(task)
    db.session.commit()

    return 'Task deleted'




@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run()