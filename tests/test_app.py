import pytest
from app import app
from flask import session
from datetime import datetime, timedelta, timezone
import os

# Use environment variables if set, otherwise default to hardcoded sandbox credentials
TEST_EMAIL = os.getenv('TEST_EMAIL', 'sandbox-email@example.com')
TEST_PASSWORD = os.getenv('TEST_PASSWORD', 'sandbox-password')

@pytest.fixture
def client():
    # Set up the Flask test client
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client

def test_login_success(client, mocker):
    # Mock the requests.post method to simulate a successful login response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=200, json=lambda: {"token": "testtoken"}))

    response = client.post('/login', data={'email': 'valid@example.com', 'password': 'validpassword'})
    assert response.status_code == 302  # Redirect to dashboard
    with client.session_transaction() as sess:
        assert 'token' in sess
        assert sess['token'] == 'testtoken'

def test_login_failure(client, mocker):
    # Mock the requests.post method to simulate a failed login response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=401))

    response = client.post('/login', data={'email': 'invalid@example.com', 'password': 'invalidpassword'})
    assert b"Invalid email or password" in response.data

def test_dashboard_access(client):
    # Simulate a session with a valid token
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b"Dashboard" in response.data

def test_dashboard_no_token(client):
    # Simulate no session token (user not logged in)
    response = client.get('/dashboard')
    assert response.status_code == 302  # Redirect to login
    assert response.headers['Location'] == '/login'


def test_report_success(client, mocker):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Mock the requests.post method to simulate a successful report response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=200, json=lambda: {"response": "report data"}))

    response = client.post('/report', data={'date-from': '2024-01-01', 'date-to': '2024-01-31'})
    assert response.status_code == 200
    assert b"report data" in response.data

def test_report_missing_fields(client):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Missing date-from and date-to fields
    response = client.post('/report', data={'date-from': '', 'date-to': ''})
    assert b"Both 'Date From' and 'Date To' are required." in response.data

def test_token_expired(client):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) - timedelta(minutes=1)  # Token expired

    response = client.get('/dashboard')
    assert response.status_code == 302  # Redirect to login
    assert response.headers['Location'] == '/login'
    with client.session_transaction() as sess:
        assert 'token' not in sess

def test_transaction_success(client, mocker):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Mock a successful transaction response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=200, json=lambda: {"transaction": "transaction data"}))

    response = client.post('/transaction', data={'transaction-id': 'valid-id'})
    assert response.status_code == 200
    assert b"transaction data" in response.data

def test_transaction_failure(client, mocker):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Mock an error response from the API
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=500))

    response = client.post('/transaction', data={'transaction-id': 'invalid-id'})
    assert b"The server encountered an error" in response.data

def test_logout(client):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'

    response = client.get('/logout')
    assert response.status_code == 302  # Redirect to login
    with client.session_transaction() as sess:
        assert 'token' not in sess
    assert response.headers['Location'] == '/login'