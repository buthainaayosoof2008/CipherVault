import os

from flask import Flask
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

from app.database import initialize_database


load_dotenv()

csrf = CSRFProtect()


def create_app():

    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
        static_url_path="/static"
    )

    # Production secret key
    secret_key = os.environ.get("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is not configured. "
            "Please set SECRET_KEY in the environment."
        )

    app.config["SECRET_KEY"] = secret_key

    # Session security
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # CSRF protection
    csrf.init_app(app)

    # Register routes
    from app.routes import main

    app.register_blueprint(main)

    # Initialize database
    initialize_database()

    return app