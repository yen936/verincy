import requests


with open('signature.sig', 'rb') as f:
    r = requests.post("http://127.0.0.1:5000/", data={'sig': f.read()})
    print(r.text)




