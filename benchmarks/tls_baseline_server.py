from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "baseline https ok"

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=("certs/wildcard.crt", "certs/wildcard.key"),
        debug=False
    )
