import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from urllib.parse import urlencode
import logging
from datetime import datetime, timedelta, timezone

logging.basicConfig(level=logging.ERROR)

app = Flask(__name__)
app.secret_key = "supersecretkey"

@app.route("/")
@app.route("/index")
def index():
	return render_template("login.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		email = request.form['email']
		password = request.form['password']
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/merchant/user/login?email={email}&password={password}"
		response = requests.post(url,json={'email': email, 'password': password})
		if response.status_code == 200:
			token = response.json()['token']
			session['token'] = token

			# Set the session to expire in 10 minutes (token lifespan)
			session['expires_at'] = datetime.now() + timedelta(minutes=10)

			return redirect(url_for('dashboard'))
		else:
			flash("Invalid email or password")
	return render_template('login.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        expires_at = session.get('expires_at')

        # Ensure both times are timezone-aware for proper comparison
        if not token or not expires_at or datetime.now(timezone.utc) > expires_at:
            flash("Your session has expired. Please log in again.")
            session.clear()  # Clear the session
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

@app.route("/dashboard")
@login_required
def dashboard():
	return render_template("dashboard.html")

@app.route("/report", methods=['GET', 'POST'])
@login_required
def report():
	token = session.get('token')

	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	if request.method == 'POST':
		fromDate = request.form.get('date-from', '').strip()
		toDate = request.form.get('date-to', '').strip()
		merchant = request.form.get('merchant', '').strip()
		acquirer = request.form.get('acquirer', '').strip()

		if not fromDate or not toDate:
			flash("Both 'Date From' and 'Date To' are required.")
			return redirect(url_for('report'))

		query_params = {
			'fromDate': fromDate,
			'toDate': toDate
		}

		if merchant:
			query_params['merchant'] = merchant
		if acquirer:
			query_params['acquirer'] = acquirer

		query_string = urlencode(query_params)
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transactions/report?{query_string}"

		headers = {
			'Authorization': token
		}

		try:
			response = requests.post(url, headers=headers)

			if response.status_code == 200:
				data = response.json()
				return render_template('report_result.html', data=data)
			else:
				flash(f"API error: {response.status_code} - {response.text}")
				return redirect(url_for('report'))

		except Exception as e:
			logging.error(f"Error during API request: {e}")
			flash("An error occurred while fetching the report. Please try again.")
			return redirect(url_for('report'))

	return render_template("report.html")

@app.route("/query", methods=['GET', 'POST'])
@login_required
def query():
	token = session.get('token')

	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	if request.method == 'POST':
		fromDate = request.form.get('fromDate', '').strip()
		toDate = request.form.get('toDate', '').strip()
		status = request.form.get('status', '').strip()
		operation = request.form.get('operation', '').strip()
		merchantId = request.form.get('merchantId', '').strip()
		acquirerId = request.form.get('acquirerId', '').strip()
		paymentMethod = request.form.get('paymentMethod', '').strip()
		errorCode = request.form.get('errorCode', '').strip()
		filterField = request.form.get('filterField', '').strip()
		filterValue = request.form.get('filterValue', '').strip()
		page = request.form.get('page', '').strip()

		query_params = {}
		if fromDate:
			query_params['fromDate'] = fromDate
		if toDate:
			query_params['toDate'] = toDate
		if status:
			query_params['status'] = status
		if operation:
			query_params['operation'] = operation
		if merchantId:
			query_params['merchantId'] = merchantId
		if acquirerId:
			query_params['acquirerId'] = acquirerId
		if paymentMethod:
			query_params['paymentMethod'] = paymentMethod
		if errorCode:
			query_params['errorCode'] = errorCode
		if filterField:
			query_params['filterField'] = filterField
		if filterValue:
			query_params['filterValue'] = filterValue
		if page:
			query_params['page'] = page

		query_string = urlencode(query_params)
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transaction/list?{query_string}"

		headers = {
			'Authorization': token
		}

		try:
			response = requests.post(url, headers=headers)

			if response.status_code == 200:
				data = response.json()
				return render_template('query_result.html', data=data)
			else:
				flash(f"API error: {response.status_code} - {response.text}")
				return redirect(url_for('query'))

		except Exception as e:
			logging.error(f"Error during API request: {e}")
			flash("An error occurred while fetching the query. Please try again.")
			return redirect(url_for('query'))

	return render_template("query.html")

@app.route("/transaction", methods=['GET', 'POST'])
@login_required
def transaction():
	token = session.get('token')

	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	error = None
	data = None

	if request.method == 'POST':
		transaction_id = request.form.get('transaction-id')

		if not transaction_id:
			error = "Transaction ID is required."
			return render_template("transaction_result.html", data=data, error=error)

		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transaction?transactionId={transaction_id}"

		headers = {
			'Authorization': token
		}

		try:
			response = requests.post(url, headers=headers)

			if response.status_code == 200:
				data = response.json()
				return render_template('transaction_result.html', data=data)

			elif response.status_code == 500:
				error = "The server encountered an error. Please check the Transaction ID and try again."
				return render_template("transaction_result.html", data=data, error=error)

			else:
				error = f"Error: {response.status_code} - {response.text}"
				return render_template("transaction_result.html", data=data, error=error)

		except Exception as e:
			error = f"An error occurred: {e}"
			return render_template("transaction_result.html", data=data, error=error)

	return render_template("transaction.html")

@app.route("/client", methods=['GET', 'POST'])
@login_required
def client():
	token = session.get('token')

	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	if request.method == 'POST':
		transaction_id = request.form.get('transaction-id')
		if not transaction_id:
			flash("Transaction ID is required.")
			return render_template("client.html")

		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/client?transactionId={transaction_id}"

		headers = {
			'Authorization': token
		}

		try:
			response = requests.post(url, headers=headers)

			if response.status_code == 200:
				data = response.json()

				if data and 'customerInfo' in data:
					return render_template('client_result.html', clientInfo=data['customerInfo'])
				else:
					flash("No client data found for the given transaction ID.")
					return render_template("client.html")

			elif response.status_code == 500:
				flash("The server encountered an error. Please check the Transaction ID and try again.")
				return render_template("client.html")

			else:
				flash("No client found or an error occurred.")
				return render_template("client.html")

		except Exception as e:
			flash(f"An error occurred: {e}")
			return render_template("client.html")

	return render_template("client.html")

@app.route('/logout')
def logout():
	session.clear()
	flash("You have been logged out successfully.")
	return redirect(url_for('login'))

if __name__ == '__main__':
	app.run(debug=True)
