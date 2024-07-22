from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)

# Set the absolute path for the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    priority = db.Column(db.String(10), nullable=False)
    is_reminder = db.Column(db.Boolean, default=False)
    reminder_datetime = db.Column(db.String(20), nullable=True)
    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    tasks = Task.query.all()
    return render_template('index.html', tasks=tasks)

@app.route('/add', methods=['POST'])
def add():
    data = request.get_json()
    name = data.get('taskName')
    date = data.get('taskDate')
    priority = data.get('taskPriority')
    is_reminder = data.get('taskReminder', False)
    reminder_date = data.get('reminderDate')
    reminder_time = data.get('reminderTime')
    reminder_datetime = f"{reminder_date} {reminder_time}" if is_reminder else None

    new_task = Task(name=name, date=date, priority=priority, is_reminder=is_reminder, reminder_datetime=reminder_datetime)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'success': True}), 201

@app.route('/delete/<int:id>', methods=['DELETE'])
def delete(id):
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    return jsonify({'success': True}), 204

@app.route('/toggle/<int:id>', methods=['POST'])
def toggle(id):
    task = Task.query.get_or_404(id)
    data = request.get_json()
    task.is_completed = data.get('completed', False)
    db.session.commit()
    return jsonify({'success': True}), 200

@app.route('/calendar')
def calendar():
    return render_template('calendar.html')

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
        'is_completed': task.is_completed
    } for task in tasks])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080)
