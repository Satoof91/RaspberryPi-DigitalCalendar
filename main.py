from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from datetime import datetime
import os
import secrets
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ensure you set a secret key for session management

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)

db = SQLAlchemy(app)
oauth = OAuth(app)

# Google OAuth configuration
oauth.register(
    name='google',
    client_id='33125742498-hvgm88r6mncmhtsv88s4b0qd50op0put.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    redirect_uri='http://localhost:8080/auth/google/callback',
    client_kwargs={'scope': 'openid profile email'}
)

# Microsoft OAuth configuration
oauth.register(
    name='microsoft',
    client_id='YOUR_MICROSOFT_CLIENT_ID',
    client_secret='YOUR_MICROSOFT_CLIENT_SECRET',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    client_kwargs={'scope': 'openid email profile'}
)

# Database model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    priority = db.Column(db.String(10), nullable=False)
    is_reminder = db.Column(db.Boolean, default=False)
    reminder_datetime = db.Column(db.String(20), nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    user_email = session.get('user_email')
    tasks = Task.query.all()
    return render_template('index.html', tasks=tasks, user_email=user_email)


@app.route('/add', methods=['POST'])
def add():
    data = request.get_json()
    name = data.get('taskName')
    date = data.get('taskDate')
    priority = data.get('taskPriority')
    is_reminder = data.get('taskReminder')
    reminder_datetime = data.get('reminderDate') + ' ' + data.get('reminderTime') if is_reminder else None

    new_task = Task(name=name, date=date, priority=priority, is_reminder=is_reminder, reminder_datetime=reminder_datetime)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/delete/<int:id>')
def delete(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/toggle/<int:id>', methods=['POST'])
def toggle(id):
    task = Task.query.get_or_404(id)
    task.is_completed = not task.is_completed
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/tasks', methods=['GET'])
def get_tasks():
    tasks = Task.query.all()
    return jsonify([{
        'id': task.id,
        'name': task.name,
        'date': task.date,
        'priority': task.priority,
        'is_reminder': task.is_reminder,
        'reminder_datetime': task.reminder_datetime,
        'is_completed': task.is_completed,
        'created_at': task.created_at
    } for task in tasks])

@app.route('/calendar')
def calendar():
    user_email = session.get('user_email')
    return render_template('calendar.html', user_email=user_email)

# Route for Google login
@app.route('/login/google')
def login_google():
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    redirect_uri = url_for('auth_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/auth/google/callback')
def auth_google():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce)
    session['user_email'] = user_info['email']
    return redirect(url_for('index'))

@app.route('/login/microsoft')
def login_microsoft():
    redirect_uri = url_for('auth_microsoft', _external=True)
    return oauth.microsoft.authorize_redirect(redirect_uri)

@app.route('/auth/microsoft/callback')
def auth_microsoft():
    token = oauth.microsoft.authorize_access_token()
    user_info = oauth.microsoft.parse_id_token(token)
    session['user_email'] = user_info
    return redirect(url_for('index'))

@app.route('/sync-tasks')
def sync_tasks():
    user_email = session.get('user_email')
    google_token = session.get('google_token')
    microsoft_token = session.get('microsoft_token')
    tasks = []

    if google_token:
        # Fetch tasks from Google
        headers = {'Authorization': f"Bearer {google_token['access_token']}"}
        response = requests.get('https://tasks.googleapis.com/tasks/v1/lists/@default/tasks', headers=headers)
        if response.status_code == 200:
            google_tasks = response.json().get('items', [])
            for gtask in google_tasks:
                task = {
                    'name': gtask.get('title'),
                    'date': gtask.get('due', '').split('T')[0],
                    'priority': 'Low',  # Default priority
                    'is_reminder': False,
                    'reminder_datetime': None,
                    'is_completed': gtask.get('status') == 'completed',
                }
                tasks.append(task)

    if microsoft_token:
        # Fetch tasks from Microsoft
        headers = {'Authorization': f"Bearer {microsoft_token['access_token']}"}
        response = requests.get('https://graph.microsoft.com/v1.0/me/tasks', headers=headers)
        if response.status_code == 200:
            microsoft_tasks = response.json().get('value', [])
            for mtask in microsoft_tasks:
                task = {
                    'name': mtask.get('title'),
                    'date': mtask.get('dueDateTime', {}).get('dateTime', '').split('T')[0],
                    'priority': 'Low',  # Default priority
                    'is_reminder': False,
                    'reminder_datetime': None,
                    'is_completed': mtask.get('status') == 'completed',
                }
                tasks.append(task)

    # Add tasks to the local database
    for task in tasks:
        if task['name'] and task['date']:
            new_task = Task(name=task['name'], date=task['date'], priority=task['priority'],
                            is_reminder=task['is_reminder'], reminder_datetime=task['reminder_datetime'],
                            is_completed=task['is_completed'])
            db.session.add(new_task)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8080)
