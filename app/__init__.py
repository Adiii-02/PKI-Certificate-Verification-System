import os

from dotenv import load_dotenv
from flask import Flask


load_dotenv()


def create_app():
    """Create and configure the Flask application."""

    app = Flask(__name__)

    secret_key = os.getenv("SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "SECRET_KEY is missing from the .env file."
        )

    app.config["SECRET_KEY"] = secret_key
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

    from app.routes.main import main_bp

    app.register_blueprint(main_bp)

    return app