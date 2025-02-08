from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Define the Users model
class Users(db.Model):
    __tablename__ = 'signup_users'
    email = db.Column(db.String(100), primary_key=True, nullable=False)
    username = db.Column(db.String(100), unique = True, primary_key=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    
    # Use default for account_created_at and don't update it after account creation
    created_at = db.Column(db.TIMESTAMP, default=datetime.now, nullable=False)
    
    # Use onupdate for updated_at to update it whenever the record is updated
    updated_at = db.Column(db.TIMESTAMP, default=datetime.now, onupdate=datetime.now, nullable=False)

# Define the Contact model
class Contact(db.Model):
    __tablename__ = 'contacts'

    sr_no = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name = db.Column(db.String(100), nullable=False)
    email_address = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=True)
    contact_timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Define the Tasks model
class Tasks(db.Model):
    __tablename__ = 'tasks'

    sr_no = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_title = db.Column(db.String(100), nullable=False)
    task_description = db.Column(db.String(200), nullable=False)
    task_priority = db.Column(db.Integer, nullable=False)
    task_status = db.Column(db.String(20), nullable=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)  # Default False
    task_created_at = db.Column(db.TIMESTAMP , default = datetime.now , nullable = False)
    task_file = db.Column(db.String(255), nullable=True)  # Store file path
    
    # Add foreign key column for username
    username = db.Column(db.String(255), db.ForeignKey('signup_users.username'), nullable=False)

    # Define relationship to access user data
    user = db.relationship('Users', backref='tasks', lazy=True)