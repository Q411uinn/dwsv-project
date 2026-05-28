# benchmarks/baseline_server.py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
