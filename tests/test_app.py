import pytest
from app import app
from flask import session
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv

load_dotenv()

# Env
TEST_EMAIL = os.getenv('TEST_EMAIL')
TEST_PASSWORD = os.getenv('TEST_PASSWORD')

@pytest.fixture
def client():
    # Set up the Flask test client
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            yield client

def test_login_success(client, mocker):
    # Access credentials from environment variables
    email = os.getenv('TEST_EMAIL')
    password = os.getenv('TEST_PASSWORD')

    # Mock the requests.post method
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=200, json=lambda: {"token": "sandbox-token"}))

    # Use the environment variables for testing
    response = client.post('/login', data={'email': email, 'password': password})
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert 'token' in sess
        assert sess['token'] == 'sandbox-token'

def test_login_failure(client, mocker):
    # Mock the requests.post method to simulate a failed login response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=401))

    response = client.post('/login', data={'email': 'asd@asd.com', 'password': 'asd'})
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


def test_report_with_data(client):
    #Login
    login_data = {
        'email': os.getenv('TEST_EMAIL'),
        'password': os.getenv('TEST_PASSWORD')
    }
    login_response = client.post('/login', data=login_data)

    assert login_response.status_code == 302

    #Date data only
    report_data = {
        'date-from': '2010-01-01',
        'date-to': '2020-01-01'
    }

    # Send the POST request to /report
    response = client.post('/report', data=report_data)

    # Ensure the response status code is 200 (successful request)
    assert response.status_code == 200

    # Check for expected currency strings and amounts in the HTML response
    # These values were manually verified via Postman
    assert b"TRY" in response.data  # Turkish Lira is expected in the response
    assert b"350961" in response.data  # Expected total amount in TRY
    assert b"RUB" in response.data  # Russian Ruble is expected
    assert b"9600" in response.data  # Expected total amount in RUB
    assert b"EUR" in response.data  # Euro is expected
    assert b"4386" in response.data  # Expected total amount in EUR
    assert b"IRR" in response.data  # Iranian Rial is expected
    assert b"3640000000" in response.data  # Expected total amount in IRR
    assert b"CNY" in response.data  # Chinese Yuan is expected
    assert b"100" in response.data  # Expected total amount in CNY



def test_token_expired(client):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) - timedelta(minutes=1)  # Token expired

    response = client.get('/dashboard')
    assert response.status_code == 302  # Redirect to login
    assert response.headers['Location'] == '/login'
    with client.session_transaction() as sess:
        assert 'token' not in sess

#mocktest, since there is no access to transaction or client data
def test_transaction_success(client, mocker):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Mock a successful transaction response
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=200, json=lambda: {"transaction": "transaction data"}))
    # Would be client information retrieval parameters here if possible
    response = client.post('/transaction', data={'transaction-id': 'success'})
    assert response.status_code == 200
    assert b"transaction data" in response.data

#mocktest, since there is no access to transaction or client data
def test_transaction_failure(client, mocker):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'
        sess['expires_at'] = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Mock an error response from the API
    mocker.patch('requests.post', return_value=mocker.Mock(status_code=500))

    response = client.post('/transaction', data={'transaction-id': 'fail'})
    assert b"The server encountered an error" in response.data

def test_logout(client):
    with client.session_transaction() as sess:
        sess['token'] = 'testtoken'

    response = client.get('/logout')
    assert response.status_code == 302  # Redirect to login
    with client.session_transaction() as sess:
        assert 'token' not in sess
    assert response.headers['Location'] == '/login'