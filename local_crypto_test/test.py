import requests


data = {'username': 'testuser',
        'domain': 'testdomain.com'}
r = requests.post("http://127.0.0.1:5000/auth", data=data)
print(r.text)
