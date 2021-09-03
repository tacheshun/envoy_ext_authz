import requests
from flask import Flask
app = Flask(__name__)


@app.route('/service')
def hello():
    return requests.get("https://httpbin.org/json").content

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080, debug=False)
