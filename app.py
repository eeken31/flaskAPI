import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from urllib.parse import urlencode
import logging


logging.basicConfig(level=logging.DEBUG)

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
		if response.status_code==200:
			session['token'] = response.json()['token']
			return redirect(url_for('dashboard'))
		else:
			flash("Invalid email or password")
	return render_template('login.html')

def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'token' not in session:
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
    # Retrieve the token from the session
    token = session.get('token')

    # If the token doesn't exist, force a login
    if not token:
        flash("Your session has expired. Please log in again.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Collect form data (Date From, Date To, Merchant, Acquirer)
        fromDate = request.form.get('date-from', '').strip()
        toDate = request.form.get('date-to', '').strip()
        merchant = request.form.get('merchant', '').strip()  # Optional
        acquirer = request.form.get('acquirer', '').strip()  # Optional

        # Validate the required fields
        if not fromDate or not toDate:
            flash("Both 'Date From' and 'Date To' are required.")
            return redirect(url_for('report'))

        # Build query parameters
        query_params = {
            'fromDate': fromDate,
            'toDate': toDate
        }

        # Add optional parameters if provided
        if merchant:
            query_params['merchant'] = merchant
        if acquirer:
            query_params['acquirer'] = acquirer

        # Encode the query parameters
        query_string = urlencode(query_params)
        url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transactions/report?{query_string}"

        headers = {
            'Authorization': token  # Use the session token for authorization
        }

        try:
            # Make the API request
            response = requests.post(url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                # Ensure data exists in the response
                if 'response' in data and data['response']:
                    return render_template('report_result.html', data=data)
                else:
                    flash("The report returned no summary data.")
                    return redirect(url_for('report'))
            else:
                # Handle non-200 responses
                flash(f"API error: {response.status_code} - {response.text}")
                return redirect(url_for('report'))

        except Exception as e:
            # Log any errors during the request
            logging.error(f"Error during API request: {e}")
            flash("An error occurred while fetching the report. Please try again.")
            return redirect(url_for('report'))

    # Render the report form on GET request
    return render_template("report.html")



@app.route("/query")
@login_required
def query():
	token = session.get('token')

	# Check if the token exists, if not, redirect to login
	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))
	return render_template("query.html")

@app.route("/transaction", methods=['GET', 'POST'])
@login_required
def transaction():
	token = session.get('token')

	# Check if the token exists, if not, redirect to login
	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	if request.method == 'POST':
		# Get the transaction ID from the form submission
		transaction_id = request.form.get('transaction-id')

		if not transaction_id:
			# Ensure the transaction ID is provided
			flash("Transaction ID is required.")
			return redirect(url_for('transaction'))

		# API URL
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transaction?transactionId={transaction_id}"

		headers = {
			'Authorization': token  # Session token
		}

		# Send GET request to the API
		response = requests.get(url, headers=headers)

		if response.status_code == 200:
			data = response.json()  # The API returns JSON

			# Ensure that data exists and is not empty
			if data and 'transaction' in data and data['transaction']:
				return render_template('transaction_result.html', data=data)
			else:
				flash("No transaction data found for the given ID.")
				return redirect(url_for('transaction'))
		else:
			flash("No transaction found or an error occurred.")
			return redirect(url_for('transaction'))

	return render_template("transaction.html")

@app.route("/client", methods=['GET', 'POST'])
@login_required
def client():
	# Retrieve the token from the session
	token = session.get('token')

	# Check if the token exists, if not, redirect to login
	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))


	if request.method == 'POST':
		# Get the transaction ID from the form submission
		transaction_id = request.form.get('transaction-id')
		if not transaction_id:
			# Ensure the transaction ID is provided
			flash("Transaction ID is required.")
			return redirect(url_for('client'))

		# API URL
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/client?transactionId={transaction_id}"

		headers = {
			'Authorization': token  # Session token
		}

		# Send POST request to the API
		response = requests.post(url, headers=headers)

		if response.status_code == 200:
			data = response.json()  # The API returns JSON

			# Ensure that 'clientInfo' exists and is not empty
			if data and 'customerInfo' in data:
				return render_template('client_result.html', clientInfo=data['customerInfo'])
			else:
				flash("No client data found for the given transaction ID.")
				return redirect(url_for('client'))
		else:
			flash("No client found or an error occurred.")
			return redirect(url_for('client'))

	return render_template("client.html")

@app.route('/logout')
def logout():
	#Clear session data and logout
	session.clear()
	flash("You have been logged out successfully.")
	return redirect(url_for('login'))



if __name__ == '__main__':
	app.run(debug=True)