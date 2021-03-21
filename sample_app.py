from flask import Flask, render_template, redirect, url_for, request


app = Flask(__name__)


@app.route('/')
def home():
    return "Hello, Successful login. Welcome to our App"  # return a string


@app.route('/dashboard')
def dashboard():
    return render_template('templates/black-dashboard-master/examples/dashboard.html')  # render a template


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('home'))
    return render_template('sample_login.html', error=error)


if __name__ == '__main__':
    app.run(debug=True)
