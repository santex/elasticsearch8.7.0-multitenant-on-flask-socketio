#!/usr/local/bin/python3.9
import os, sys, pprint
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from flask_cors import CORS
from threading import Lock



from flask import Flask, render_template, session, request, \
    copy_current_request_context, jsonify,  make_response

from flask_socketio import SocketIO, emit, join_room, leave_room, \
    close_room, rooms, disconnect


import subprocess
from subprocess import Popen, PIPE

from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# Set this variable to "threading", "eventlet" or "gevent" to test the
# different async modes, or leave it set to None for the application to choose
# the best option based on installed packages.
async_mode =  None
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret tails! the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions

cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)
auth = HTTPBasicAuth()
"""
$ curl -i http://localhost:5000/todo/api/v1.0/tasks
$ curl -i http://localhost:5000/todo/api/v1.0/tasks/2
$ curl -i http://localhost:5000/todo/api/v1.0/tasks/3
$ curl -i http://localhost:5000/todo/api/v1.0/tasks/3
$ curl -i -H "Content-Type: application/json" -X POST -d '{"title":"Read a book"}' http://localhost:5000/todo/api/v1.0/tasks
$ curl -i http://localhost:5000/todo/api/v1.0/tasks
$ curl -i -H "Content-Type: application/json" -X PUT -d '{"done":true}' http://localhost:5000/todo/api/v1.0/tasks/2
$ curl -i http://localhost:5000/todo/api/v1.0/tasks
$ curl -i http://localhost:5000/todo/api/v1.0/tasks
$ curl -u santex:python -i http://localhost:5000/todo/api/v1.0/tasks
$ curl -u santex:python -i http://localhost:5000/todo/api/v1.0/tasks
"""

socketio = SocketIO(app, async_mode=async_mode)
thread = None
thread_lock = Lock()

def connect2ES():
  url = {'scheme':os.environ.get('ELASTIC_SCHEME'),
         'host': os.environ.get('ELASTIC_HOST'),
         'port': int(os.environ.get('ELASTIC_PORT'))}

  if os.environ.get('ELASTIC_PASS'):
    es = Elasticsearch([url],basic_auth=(os.environ.get('ELASTIC_USER'),os.environ.get('ELASTIC_PASS')))
  else:
    es = Elasticsearch([url])

  es.options(ignore_status=[400,404])

  if es.ping():
    print('Connected to ES!')
  else:
    print('Not Connected to ES!')
    sys.exit()

  return es



def get_data():
  
    code = subprocess.check_output(["/usr/local/bin/python3.9", "subproc.py"])

    pprint.pprint (code , compact=True, indent=4)


    return code



def background_thread():
    """Example of how to send server generated events to clients."""
    count = 0
      
    es = connect2ES()


    while True:
        socketio.sleep(.1)
        count += 1
        
        socketio.emit('my_response',
                      {'data': 'Server generated event', 'count': count,'date':get_data()})



class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/v1.0/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
        
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
        
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/v1.0/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/v1.0/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': str(token), 'duration': 600})


@app.route('/api/v1.0/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})



tasks = [
    {
        'id': 1,
        'title': u'Buy groceries',
        'description': u'Milk, Cheese, Pizza, Fruit, Tylenol', 
        'done': False
    },
    {
        'id': 2,
        'title': u'Learn Python',
        'description': u'Need to find a good Python tutorial on the web', 
        'done': False
    }
]


@app.route('/api/v1.0/tasks', methods=['POST'])
def create_task():
    if not request.json or not 'title' in request.json:
        abort(400)
    task = {
        'id': tasks[-1]['id'] + 1,
        'title': request.json['title'],
        'description': request.json.get('description', ""),
        'done': False
    }
    tasks.append(task)
    return jsonify({'task': task}), 201
    
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


#curl -i http://localhost:5000/api/v1.0/tasks/2
@app.route('/api/v1.0/tasks', methods=['GET'])
def get_tasks():
    return jsonify({'tasks': tasks})

#curl -i http://localhost:5000/api/v1.0/tasks/2
@app.route('/api/v1.0/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    task = [task for task in tasks if task['id'] == task_id]
    if len(task) == 0:
        abort(404)
    return jsonify({'task': task[0]})
    
@app.route("/") 
def index():
    return render_template('index.html', async_mode=socketio.async_mode)


@socketio.event
def my_event(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']})


@socketio.event
def my_broadcast_event(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         broadcast=True)


@socketio.event
def join(message):
    join_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'In rooms: ' + ', '.join(rooms()),
          'count': session['receive_count']})


@socketio.event
def leave(message):
    leave_room(message['room'])
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': 'In rooms: ' + ', '.join(rooms()),
          'count': session['receive_count']})


@socketio.on('close_room')
def on_close_room(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response', {'data': 'Room ' + message['room'] + ' is closing.',
                         'count': session['receive_count']},
         to=message['room'])
    close_room(message['room'])


@socketio.event
def my_room_event(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    emit('my_response',
         {'data': message['data'], 'count': session['receive_count']},
         to=message['room'])


@socketio.event
def disconnect_request():
    @copy_current_request_context
    def can_disconnect():
        disconnect()

    session['receive_count'] = session.get('receive_count', 0) + 1
    # for this emit we use a callback function
    # when the callback function is invoked we know that the message has been
    # received and it is safe to disconnect
    emit('my_response',
         {'data': 'Disconnected!', 'count': session['receive_count']},
         callback=can_disconnect)


@socketio.event
def my_ping():
    emit('my_pong')


@socketio.event
def connect():
    global thread
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)
    emit('my_response', {'data': 'Connected', 'count': 0})


@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected', request.sid)


#if __name__ == '__main__':
  #socketio.run(app, host=os.environ.get('CONTROL_FLASK_HOST'),port=os.environ.get('CONTROL_FLASK_PORT'))
  
"""
curl  -F "user=default" -F "profile=default" -X POST -F file=@"output.mp4" http://127.0.0.1:6969/add_file
curl  -F "user=default" -F "profile=default" -X POST -F file=@"/Volumes/Untitled/message.mp4" http://127.0.0.1:6969/add_file
"""
