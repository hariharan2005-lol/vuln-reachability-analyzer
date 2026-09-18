from flask import Flask, request
from dummy_vuln_lib import unsafe_deserialize

app = Flask(__name__)


def parse_input(data):
    """Parses raw user input using an unsafe library deserializer."""
    return unsafe_deserialize(data)


def process_user(username, payload):
    """Processes user details and calls parser."""
    print(f"Processing user: {username}")
    return parse_input(payload)


@app.route("/login", methods=["POST"])
def login():
    """Vulnerable entry point reaching unsafe_deserialize."""
    username = request.form.get("username", "guest")
    token = request.form.get("token", "")
    res = process_user(username, token)
    return {"status": "ok", "result": res}


def safe_helper():
    return "Sanitized safe output"


@app.route("/safe", methods=["GET"])
def safe_endpoint():
    """Safe entry point that does not reach any vulnerable function."""
    return safe_helper()


def dead_code():
    """Unreachable dead code calling unsafe deserializer (not reachable from any route)."""
    return unsafe_deserialize("dummy")


if __name__ == "__main__":
    app.run(port=5000)
