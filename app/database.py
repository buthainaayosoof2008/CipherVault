import os
import sqlite3


DATABASE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "instance"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "users.db"
)


def get_database():
    """
    Connect to the CipherVault SQLite database.
    """

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """
    Create the users table if it does not already exist.
    """

    connection = get_database()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()