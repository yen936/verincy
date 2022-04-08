from flask import Flask, render_template, redirect, url_for, request
import requests

app = Flask(__name__, template_folder='templates/black-dashboard-master/examples')


@app.route('/')
def home():
    return "Hello, Welcome to our App"  # return a string


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # render a template


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':

        url = "http://127.0.0.1:5000/auth"
        data = {'username': request.form['username'],
                'domain': "testdomain.com"}

        response = requests.post(url=url, data=data)
        if request.form['username'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('dashboard'))

        print(response)

        # if response != 'verified':
        #     error = 'Invalid Credentials. Please try again.'
        # else:
        #     return redirect(url_for('home'))

    return render_template('sample_login.html', error=error)


if __name__ == '__main__':
    app.run(debug=True, port=8000)
