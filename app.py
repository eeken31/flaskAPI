import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from urllib.parse import urlencode

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

	# Check if the token exists, if not, redirect to login
	if not token:
		flash("Your session has expired. Please log in again.")
		return redirect(url_for('login'))

	if request.method == 'POST':
		fromDate = request.form['date-from']
		toDate = request.form['date-to']
		merchant = request.form.get('merchant', '')  # Get the merchant, empty if not provided
		acquirer = request.form.get('acquirer', '')  # Get the acquirer, empty if not provided

		if not fromDate or not toDate:
			# Ensure required fields are provided
			flash("Both 'Date From' and 'Date To' are required.")
			return redirect(url_for('report'))

		# Build query parameters dynamically
		query_params = {
			'fromDate': fromDate,
			'toDate': toDate
		}

		if merchant:
			query_params['merchant'] = merchant

		if acquirer:
			query_params['acquirer'] = acquirer

		# Use urlencode to build the query string properly
		query_string = urlencode(query_params)
		url = f"https://sandbox-reporting.rpdpymnt.com/api/v3/transactions/report?{query_string}"
		print(url)

		# Make the request and include the token in the Authorization header
		headers = {
			'Authorization': f'Bearer {token}'  # Include the session token in the request
		}

		# Send the POST request with the headers and parameters
		response = requests.post(url, headers=headers, json={
			'fromDate': fromDate,
			'toDate': toDate,
			'merchant': merchant,
			'acquirer': acquirer
		})

		if response.status_code == 200:
			data = response.json()  # The API returns JSON
			return render_template('report_result.html', data=data)
		else:
			flash("No report found.")

	return render_template("report.html")

@app.route("/query")
@login_required
def query():
	return render_template("query.html")

@app.route("/transaction")
@login_required
def transaction():
	return render_template("transaction.html")

@app.route("/client")
@login_required
def client():
	return render_template("client.html")

@app.route('/logout')
def logout():
    """Log out the user by clearing the session and redirecting to the login page."""
    session.clear()  # This clears all the session data
    flash("You have been logged out successfully.")  # Optional: Flash a logout message
    return redirect(url_for('login'))  # Redirect to the login page after logout



if __name__ == '__main__':
	app.run(debug=True)