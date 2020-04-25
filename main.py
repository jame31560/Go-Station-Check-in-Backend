from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
import hashlib
import datetime
import json

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config')
app.config.from_pyfile('config.py')


jwt = JWTManager()
jwt.init_app(app)


db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(128))
    status = db.Column(db.Integer)
    nick = db.Column(db.String(30))
    history = db.relationship('History', backref='user')

    def __init__(self, email, password, status, nick):
        self.email = email
        self.password = password
        self.status = status
        self.nick = nick


class History(db.Model):
    __tablename__ = 'history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    gostation_id = db.Column(db.String(200))
    datetime = db.Column(db.DateTime(), default=datetime.datetime.utcnow)

    def __init__(self, user_id, gostation_id, datetime=None):
        self.user_id = user_id
        self.gostation_id = gostation_id
        self.datetime = datetime


def hash_str(inp_str):
    sha512 = hashlib.sha512()
    sha512.update(inp_str.encode('utf-8'))
    return sha512.hexdigest()


@app.route("/register", methods=["POST"])
def add_user():
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 400
    try:
        email = request.json["email"]
        password = hash_str(request.json["password"])
        nick = request.json["nick"]
        status = 0
        new_user = User(email, password, status, nick)
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        return jsonify(msg="帳號已存在"), 202
    except KeyError:
        return jsonify(msg="輸入不正確"), 400
    return jsonify(msg="SUCCESS", data={}), 201


@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 400
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    keep_login = request.json.get("keep_login", None)
    if not email:
        return jsonify(msg="Missing email parameter"), 400
    if not password:
        return jsonify(msg="Missing password parameter"), 400
    user = User.query.filter_by(
        email=email, password=hash_str(password)).first()
    if user is None:
        return jsonify(msg="Bad username or password"), 401
    # Identity can be any data that is json serializable
    expires = datetime.timedelta(days=365 if keep_login else 1)
    access_token = create_access_token(
        identity={"email": email, "user_id": user.id}, expires_delta=expires)
    return jsonify(access_token=access_token), 201


@app.route('/history', methods=['GET'])
@jwt_required
def get_historys():
    current_user = get_jwt_identity()
    historys = History.query.filter_by(
        user_id=current_user["user_id"]).order_by(History.datetime.desc())
    result = []
    for each in historys:
        result.append({
            "id": each.id,
            "gostation_id": each.gostation_id,
            "user_id": each.user_id,
            "datetime": each.datetime
        })
    return jsonify({"data": result, "msg": "SUCCESS"}), 200


@app.route('/history/<id>', methods=['DELETE'])
@jwt_required
def delete_history(id):
    current_user = get_jwt_identity()
    history = History.query.get(id)
    if history:
        if history.user_id != current_user["user_id"]:
            return jsonify({"msg": "權限不足"}), 403
    db.session.delete(history)
    db.session.commit()
    return jsonify({"msg": "SUCCESS"}), 200


@app.route('/checkin', methods=['POST'])
@jwt_required
def checkin():
    if not request.is_json:
        return jsonify(msg="Missing JSON in request"), 400
    gostation_id = request.json.get('gostation_id', None)
    if not gostation_id:
        return jsonify(msg="Missing gostation_id parameter"), 400
    current_user = get_jwt_identity()
    new_record = History(current_user["user_id"], gostation_id)
    db.session.add(new_record)
    db.session.commit()
    return jsonify({"data": {
        "id": new_record.id,
        "user_id": new_record.user_id,
        "gostation_id": new_record.gostation_id,
        "datetime": new_record.datetime
    },
        "msg": "SUCCESS"}), 201


if __name__ == '__main__':
    app.run()
