import os

import mysql.connector
from dotenv import load_dotenv
from mysql.connector import Error


load_dotenv()


def get_db_config():
    """Load the MySQL configuration from environment variables."""

    required_variables = [
        "DB_HOST",
        "DB_PORT",
        "DB_NAME",
        "DB_USER",
        "DB_PASSWORD",
    ]

    missing_variables = [
        variable
        for variable in required_variables
        if not os.getenv(variable)
    ]

    if missing_variables:
        missing = ", ".join(missing_variables)
        raise RuntimeError(
            f"Missing required database environment variables: {missing}"
        )

    try:
        port = int(os.getenv("DB_PORT"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "DB_PORT must contain a valid integer."
        ) from exc

    return {
        "host": os.getenv("DB_HOST"),
        "port": port,
        "database": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
    }


def get_db_connection():
    """Create and return a MySQL connection."""

    try:
        connection = mysql.connector.connect(**get_db_config())

        if not connection.is_connected():
            raise RuntimeError(
                "The MySQL connection could not be established."
            )

        return connection

    except Error as exc:
        raise RuntimeError(
            "Unable to connect to the PKI database. "
            "Check that MySQL is running and the .env settings are correct."
        ) from exc


def close_db_connection(connection):
    """Safely close a MySQL connection."""

    if connection is not None and connection.is_connected():
        connection.close()