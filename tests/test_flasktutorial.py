import pytest
from flask import url_for
from werkzeug.security import generate_password_hash
from flasktutorial import app, db, Users, Tasks
from datetime import datetime

@pytest.fixture
def client():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use in-memory SQLite database for testing
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

# Test Home Page
def test_home_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"Home" in response.data

# Test Login Page
def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b"login" in response.data

# Test Login with Correct and Incorrect Credentials
def test_successful_login(client):
    with app.app_context():
        hashed_password = generate_password_hash("testpassword", method="pbkdf2:sha256")
        user = Users(email="test@example.com", username='testuser', password=hashed_password)
        db.session.add(user)
        db.session.commit()

    response = client.post('/login', data={'username': 'testuser', 'password': 'testpassword'})
    assert response.status_code == 302  # Redirect to dashboard

def test_unsuccessful_login(client):
    response = client.post('/login', data={'username': 'testuser', 'password': 'wrongpassword'})
    assert response.status_code == 200
    assert b"Incorrect password, please try again.", 'danger' in response.data

# Test Signup Page
def test_signup_page(client):
    response = client.get('/signup')
    assert response.status_code == 200
    assert b"Signup" in response.data

def test_signup_existing_email(client):
    with app.app_context():
        hashed_password = generate_password_hash("testpassword", method="pbkdf2:sha256")
        user = Users(email="test@example.com", username="testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

    response = client.post('/signup', data={'email': 'test@example.com', 'username': 'newuser', 'password': 'newpassword', 'confirm_password': 'newpassword'})
    assert b"This email is already registered.", 'danger' in response.data

def test_signup_with_existing_username(client) :
    with app.app_context():
        hashed_password = generate_password_hash("testpassword", method="pbkdf2:sha256")
        user = Users(email = "newemail@gmail.com", username = "testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

    response = client.post('/signup', data = {'email' : 'newemail@gmail.com', 'usename' : 'testuser', 'password' : 'newpassword', 'confirm_password' : 'newpassword'})
    assert b"This username is already taken.", 'danger'

def test_dashboard_page_logged_in(client) :
    with app.app_context():
        hashed_password = generate_password_hash("testpassword", method="pbkdf2:sha256")
        user = Users(email = "test@example.com", username = "testuser", password = hashed_password)
        db.session.add(user)
        db.session.commit()

    client.post('/login', data={'username' : 'testuser', 'password' : 'testpassword'})

    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b"Dashboard" in response.data

def test_dashboard_page_not_logged_in(client) :
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert b"You must be logged in to access the dashboard.", 'warning'