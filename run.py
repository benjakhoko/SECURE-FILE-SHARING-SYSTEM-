"""Development entry point.

Run with:
    python run.py
or:
    flask --app run.py run --debug
"""

from app import create_app

app = create_app()


if __name__ == "__main__":
    # Debug mode is convenient locally; use a WSGI server (with HTTPS) in production.
    app.run(host="127.0.0.1", port=5000, debug=True)
