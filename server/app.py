import flask
from flask import Flask,render_template, request, jsonify, make_response, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager,jwt_required,create_access_token
from flask_mail import Mail, Message
from sqlalchemy import Column, Integer,String, Float, Boolean
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sendgrid
from sendgrid.helpers.mail import *
import json
import os
#import addon
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import requests
from functools import wraps
import re

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///' + os.path.join(basedir,'users.db')
app.config['SECRET_KEY']='secret-key'

db=SQLAlchemy(app)
@app.cli.command('dbCreate')
def db_create():
    db.create_all()
    print('Database created')

@app.cli.command('dbDrop')
def db_drop():
    db.drop_all()
    print('Database Dropped')

@app.cli.command('dbSeed')
def db_seed():
    hashed_password=generate_password_hash('password', method='sha256')
    testUser=User(firstName='User',
                    lastName='Test',
                             email='test@gmail.com',
                             school='Yale University',
                             program = 'Computer Engineering',
                             bio = 'This is a bio',
                             aboutMe = 'I am a person',
                             location = 'USA',
                             lookingFor = 'Mentor',
                             linkedln = 'https://www.linkedin.com/in/rishanratnasivam/',
                             skills = 'sucking at life, league',
                             interests = 'wrist action',
                             password=hashed_password,
                             public_id=str(uuid.uuid4()),
                             )
    db.session.add(testUser)
    db.session.commit()
    print('Seeded')


class User(db.Model):
    id=Column(Integer, primary_key=True)
    public_id=Column(String(50), unique=True)
    firstName=Column(String(50))
    lastName=Column(String(50))
    email=Column(String(50), unique=True)
    school=Column(String(50))
    program=Column(String(50))
    bio = Column(String())
    aboutMe = Column(String())
    password=Column(String(50))
    location = Column(String())
    lookingFor = Column(String())
    linkedln = Column(String())
    skills = Column(String())
    interests = Column(String())

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-tokens' in request.headers:
            token=request.headers['x-access-tokens']
        if not token:
            return jsonify(message='Token is missing'),401
        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify(message='Token is invalid'),401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/register', methods = ['POST'])
def register():
    data = request.json
    emailUser = data['email']

    test = User.query.filter_by(email=emailUser).first()

    if test:
        return jsonify(message='A user with this email already exists.'), 409
    if data['firstName']=="":
        return jsonify(message="Enter a first name")
    if data['lastName']=="":
        return jsonify(message="Enter a last name")
    if not re.search(regex,data['email']):
        return jsonify(message="Invalid email")
    if len(data['password'])<8:
        return jsonify(message="Password must be more then 8 characters")
    if data['password'] != data['confirmPassword']:
        return jsonify(message='Passwords do not match')
    if data['program'] == "":
        return jsonify(message='Enter a program')
    if data['bio'] == "":
        return jsonify(message='Enter a bio')
    if data['school'] == "":
        return jsonify(message='Enter a school')
    if data['aboutMe'] == "":
        return jsonify(message='Enter an about me')
    if data['location'] == "":
        return jsonify(message='Enter a location')
    if data['lookingFor'] == "":
        return jsonify(message='Enter what are you looking for')
    if data['skills'] == "":
        return jsonify(message='Enter your skills')
    if data['linkedin'] == "":
        return jsonify(message='Enter your linkedin')
    if data['interests'] == "":
        return jsonify(message="Enter your interest")
    
    hashed_password=generate_password_hash(data['password'], method='sha256')

    new_user = User(
        firstName=data['firstName'],
        lastName=data['lastName'],
        email=data['email'],
        school=data['school'],
        program = data['program'],
        bio = data['bio'],
        aboutMe = data['aboutMe'],
        location = data['location'],
        lookingFor = data['lookingFor'],
        linkedln = data['linkedin'],
        skills = data['skills'],
        interests = data['interests'],
        password=hashed_password,
        public_id=str(uuid.uuid4()),
    )

    db.session.add(new_user)
    db.session.commit()
    return jsonify(message='User Created'),201

@app.route('/api/login', methods=['POST'])
def login():
    login=request.json

    user=User.query.filter_by(email=login['email']).first()

    if not user:
        return jsonify(message='A user with this email does not exist.')
    if check_password_hash(user.password,login['password']):
        token=jwt.encode({'public_id': user.public_id,'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify(token=token.decode('UTF-8'))
    else:
        return jsonify(message='Your email or password is incorrect'),401
    
if __name__ == "__main__":
    app.run(debug=True)