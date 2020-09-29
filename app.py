import jwt
from flask import Flask, request, jsonify, session, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from sqlalchemy import or_, and_

#Init app
app = Flask(__name__)

#Database
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://mhjesjsubphtbs:c9ec4cf31deaff1a59ddfbea18c761f15fc0aa50d14c289e1f7373ad45b24782@ec2-54-160-161-214.compute-1.amazonaws.com:5432/d2qtiesnf6mfe8"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'ilay-friedman'
db = SQLAlchemy(app)

class Users(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True)
    password = db.Column(db.String)

    def __init__(self,username,password):
        self.username = username
        self.password = password

class Messages(db.Model):
    _id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)
    msg_body = db.Column(db.String)
    msg_subject = db.Column(db.String)
    creation_date = db.Column(db.Date)
    msg_read_by_rec = db.Column(db.Boolean)

    def __init__(self,sender_id,receiver_id,msg_subject,msg_body,creation_date):
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.msg_subject = msg_subject
        self.msg_body = msg_body
        self.msg_read_by_rec = False
        self.creation_date = creation_date

def token_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = None
        if 'token' in request.headers:
            token = request.headers['token']

        if not token:
            return make_response('Access denied. No token provided.', 401)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(username=data['username']).first()
        except:
            return make_response('Invalid token.', 401)

        return func(current_user, *args, **kwargs)
    return wrapped

def messages_schema(source):
    userMessages = []
    for message in source:
        message_data = {}
        message_data['_id'] = message._id
        message_data['sender_id'] = message.sender_id
        message_data['receiver_id'] = message.receiver_id
        message_data['msg_subject'] = message.msg_subject
        message_data['msg_body'] = message.msg_body
        message_data['creation_date'] = message.creation_date
        message_data['msg_read_by_rec'] = message.msg_read_by_rec
        userMessages.append(message_data)
    return userMessages

@app.route('/')
def home():
    return ("'<h1>Messaging System API: Ilay Friedman</h1>"
            "<br><br>"
            "<b>POST</b> /register<br>"
            "<b>POST</b> /login<br>"
            "<b>POST</b> /createMessage<br>"
            "<b>GET</b> /getAllUserMessages<br>"
            "<b>GET</b> /getAllUserUnreadMessages<br>"
            "<b>POST</b> /readMessage<br>"
            "<b>POST</b> /deleteMessage")


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or not data['username'] or 'password' not in data or not data['password']:
        return make_response('Request is missing fields: username, password.', 400)
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = Users(username=data['username'], password=hashed_password)

    db.session.add(new_user)
    try:
        db.session.commit()
        return make_response("User successfully registered!", 200)

    except IntegrityError as e:
        return make_response("Server error occured (usernames are unique).", 500)

@app.route('/login', methods=['POST'])
def login():
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return make_response('Request is missing fields: username, password.', 400)
        user = Users.query.filter_by(username=auth.username).first()

        if not user:
            return make_response('No such user.', 404)

        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'username': auth.username}, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')})

        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    except:
        make_response("Server error occured: while creating message", 500)

@app.route('/createMessage', methods=['POST'])
@token_required
def create_message(current_user):
    data = request.get_json()
    if not data or 'msg_subject' not in data or not data['msg_subject'] or 'msg_body' not in data or not data['msg_body'] or 'receiver_username' not in data or not data['receiver_username']:
        return make_response("Request is missing fields: msg_subject, msg_body and receiver_username are required. The message was not sent", 400)

    #convert username to receiver id
    receiver_id = None
    try:
        receiver_id = db.session.query(Users).filter_by(username=data['receiver_username']).first()._id
    except:
        return make_response("Server error occured: while fetching user' id", 500)
    new_msg = Messages(sender_id=current_user._id,receiver_id=receiver_id, msg_subject = data['msg_subject'], msg_body = data['msg_body'], creation_date = datetime.datetime.now())

    try:
        db.session.add(new_msg)
        db.session.commit()
        return make_response("Message sent successfully to user '" + data['receiver_username'] + "'!", 200)
    except:
        return make_response("Server error occured: while creating message", 500)


@app.route('/getAllUserMessages')
@token_required
def get_all_user_messages(current_user):
    try:
        messages = db.session.query(Messages).filter_by(receiver_id=current_user._id).all()
        return make_response(jsonify({'Your messages': messages_schema(messages)}),200)
    except:
        return make_response("Server error occured", 500)


@app.route('/getAllUserUnreadMessages')
@token_required
def get_all_unread_ser_messages(current_user):
    try:
        messages = db.session.query(Messages).filter_by(receiver_id=current_user._id,msg_read_by_rec=False).all()
        return make_response(jsonify({'Your messages': messages_schema(messages)}),200)
    except:
        return make_response("Server error occured", 500)


@app.route('/readMessage', methods=['POST'])
@token_required
def read_message(current_user):
    data = request.get_json()
    if not data or 'messageId' not in data or not data['messageId']:
        return make_response("Request is missing/wrong fields: messageId.", 400)
    try:
        curr_msg = db.session.query(Messages).filter_by(_id = str(data['messageId']), receiver_id = current_user._id).first()
        if not curr_msg:
            curr_msg = db.session.query(Messages).filter_by(_id=str(data['messageId']), sender_id=current_user._id).first()
            if not curr_msg:
                return make_response("The message with id '" + str(data['messageId']) + "' was not found in your messages.", 404)
            return make_response(jsonify(messages_schema([curr_msg])[0]), 200)

        curr_msg.msg_read_by_rec = True
        db.session.commit()
        return make_response(jsonify(messages_schema([curr_msg])[0]), 200)
    except:
        return make_response("Server error occured", 500)


@app.route('/deleteMessage', methods=['POST'])
@token_required
def delete_msg(current_user):
    data = request.get_json()
    if not data or 'messageId' not in data or not data['messageId']:
        return make_response("Request is missing/wrong fields: messageId.", 400)
    try:
        msg = db.session.query(Messages).filter_by(_id=str(request.json['messageId']), sender_id=current_user._id).first()
        if not msg:
            msg = db.session.query(Messages).filter_by(_id=str(request.json['messageId']),receiver_id=current_user._id).first()
            if not msg:
                return make_response("The message with id '" + str(request.json['messageId']) + "' was not found/deleted. Deletion allowed Only as message' owners / receivers", 404)

        db.session.delete(msg)
        db.session.commit()
        return make_response("The message with id '" + str(data['messageId']) + "' was deleted successfully!", 200)
    except:
        return make_response("Server error occured", 500)


#Run Server
if __name__ == '__main__':
    app.run()
