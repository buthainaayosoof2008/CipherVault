from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    session,
    make_response,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

import re
import sqlite3

from app.database import get_database

from app.crypto import (
    analyze_crypto_algorithm,
    calculate_password_entropy,
    calculate_security_score,
    caesar_brute_force,
    decrypt_message,
    demonstrate_key_derivation,
    encrypt_message,
    find_toy_collision,
    generate_hashes,
    generate_security_report,
)


main = Blueprint("main", __name__)


# ============================================================
# SECURITY LIMITS
# ============================================================

MAX_USERNAME_LENGTH = 30
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
MAX_MESSAGE_LENGTH = 10000
MAX_ENCRYPTED_MESSAGE_LENGTH = 20000
MAX_TEXT_LENGTH = 10000
MAX_CIPHERTEXT_LENGTH = 10000
MAX_ALGORITHM_LENGTH = 50

ALLOWED_KEY_LENGTHS = {
    128,
    192,
    256,
}


# ============================================================
# SECURITY RESPONSE HEADERS
# ============================================================

@main.after_request
def add_security_headers(response):
    """
    Add basic security-related HTTP response headers.
    """

    # Prevent browsers from MIME-sniffing responses.
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent the page from being embedded in frames.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    # Reduce information sent in the Referer header.
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Disable browser features that the application does not need.
    response.headers["Permissions-Policy"] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=()"
    )

    # Prevent caching of CipherVault responses.
    response.headers["Cache-Control"] = "no-store"

    return response


# ============================================================
# AUTHENTICATION HELPER
# ============================================================

def login_required():
    """
    Check whether the current user is authenticated.
    """

    return session.get("logged_in") is True


# ============================================================
# INPUT VALIDATION HELPERS
# ============================================================

def get_json_data():
    """
    Safely retrieve JSON request data.

    Returns:
        dict or None
    """

    if not request.is_json:
        return None

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return None

    return data


def validate_length(value, maximum):
    """
    Check whether a string is within the allowed length.
    """

    if not isinstance(value, str):
        return False

    return len(value) <= maximum


def valid_username(username):
    """
    Allow letters, numbers, underscore and hyphen.
    """

    if not username:
        return False

    if len(username) < 3:
        return False

    if len(username) > MAX_USERNAME_LENGTH:
        return False

    return re.fullmatch(
        r"[A-Za-z0-9_-]+",
        username
    ) is not None


def valid_email(email):
    """
    Basic email format validation.
    """

    if not email:
        return False

    if len(email) > MAX_EMAIL_LENGTH:
        return False

    return re.fullmatch(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ) is not None


def api_error(message, status_code=400):
    """
    Return a consistent API error response.
    """

    return jsonify({
        "success": False,
        "error": message
    }), status_code


# ============================================================
# LOGIN
# ============================================================

@main.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            return render_template(
                "login.html",
                error="Please enter your username and password."
            )

        if len(username) > MAX_USERNAME_LENGTH:

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        if len(password) > MAX_PASSWORD_LENGTH:

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        connection = get_database()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # Prevent session fixation.
            session.clear()

            session["logged_in"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(
                url_for("main.home")
            )

        return render_template(
            "login.html",
            error="Invalid username or password."
        )

    return render_template(
        "login.html"
    )


# ============================================================
# REGISTER
# ============================================================

@main.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # Required fields
        # ----------------------------------------------------

        if not username or not email or not password:

            return render_template(
                "register.html",
                error="Please fill in all required fields."
            )

        # ----------------------------------------------------
        # Username validation
        # ----------------------------------------------------

        if not valid_username(username):

            return render_template(
                "register.html",
                error=(
                    "Username must be 3-30 characters and "
                    "contain only letters, numbers, '_' or '-'."
                )
            )

        # ----------------------------------------------------
        # Email validation
        # ----------------------------------------------------

        if not valid_email(email):

            return render_template(
                "register.html",
                error="Please enter a valid email address."
            )

        # ----------------------------------------------------
        # Password validation
        # ----------------------------------------------------

        if len(password) < 8:

            return render_template(
                "register.html",
                error="Password must contain at least 8 characters."
            )

        if len(password) > MAX_PASSWORD_LENGTH:

            return render_template(
                "register.html",
                error="Password is too long."
            )

        # ----------------------------------------------------
        # Confirm password
        # ----------------------------------------------------

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        connection = get_database()

        try:

            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                   OR email = ?
                """,
                (
                    username,
                    email
                )
            ).fetchone()

            if existing_user:

                return render_template(
                    "register.html",
                    error="Username or email already exists."
                )

            password_hash = generate_password_hash(
                password
            )

            connection.execute(
                """
                INSERT INTO users (
                    username,
                    email,
                    password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    email,
                    password_hash
                )
            )

            connection.commit()

        except sqlite3.IntegrityError:

            connection.rollback()

            return render_template(
                "register.html",
                error="Username or email already exists."
            )

        finally:

            connection.close()

        return redirect(
            url_for(
                "main.login",
                registered="true"
            )
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@main.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("main.login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@main.route("/")
def home():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "index.html"
    )


# ============================================================
# PAGE ROUTES
# ============================================================

@main.route("/secure-message")
def secure_message():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "secure_message.html"
    )


@main.route("/weak-crypto")
def weak_crypto():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "weak_crypto.html"
    )


@main.route("/hash-playground")
def hash_playground():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "hash_playground.html"
    )


@main.route("/attack-simulator")
def attack_simulator():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "attack_simulator.html"
    )


@main.route("/security-score")
def security_score():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "security_score.html"
    )


@main.route("/key-derivation")
def key_derivation():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "key_derivation.html"
    )


@main.route("/entropy")
def entropy():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "entropy.html"
    )


@main.route("/hash-collision")
def hash_collision():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "hash_collision.html"
    )


@main.route("/security-report")
def security_report():

    if not login_required():

        return redirect(
            url_for("main.login")
        )

    return render_template(
        "security_report.html"
    )


# ============================================================
# API AUTHENTICATION CHECK
# ============================================================

def api_login_required():

    if not login_required():

        return api_error(
            "Authentication required.",
            401
        )

    return None


# ============================================================
# AES-256-GCM ENCRYPTION
# ============================================================

@main.route("/api/encrypt", methods=["POST"])
def api_encrypt():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    message = data.get(
        "message",
        ""
    )

    password = data.get(
        "password",
        ""
    )

    if not isinstance(message, str):

        return api_error(
            "Message must be text."
        )

    if not isinstance(password, str):

        return api_error(
            "Password must be text."
        )

    if not message:

        return api_error(
            "Message cannot be empty."
        )

    if not password:

        return api_error(
            "Password cannot be empty."
        )

    if not validate_length(
        message,
        MAX_MESSAGE_LENGTH
    ):

        return api_error(
            "Message is too long."
        )

    if not validate_length(
        password,
        MAX_PASSWORD_LENGTH
    ):

        return api_error(
            "Password is too long."
        )

    try:

        encrypted_message = encrypt_message(
            message,
            password
        )

        return jsonify({
            "success": True,
            "encrypted_message": encrypted_message
        })

    except Exception:

        return api_error(
            "Encryption failed.",
            500
        )


# ============================================================
# AES-256-GCM DECRYPTION
# ============================================================

@main.route("/api/decrypt", methods=["POST"])
def api_decrypt():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    encrypted_message = data.get(
        "encrypted_message",
        ""
    )

    password = data.get(
        "password",
        ""
    )

    if not isinstance(encrypted_message, str):

        return api_error(
            "Encrypted message must be text."
        )

    if not isinstance(password, str):

        return api_error(
            "Password must be text."
        )

    if not encrypted_message:

        return api_error(
            "Encrypted message cannot be empty."
        )

    if not password:

        return api_error(
            "Password cannot be empty."
        )

    if not validate_length(
        encrypted_message,
        MAX_ENCRYPTED_MESSAGE_LENGTH
    ):

        return api_error(
            "Encrypted message is too long."
        )

    if not validate_length(
        password,
        MAX_PASSWORD_LENGTH
    ):

        return api_error(
            "Password is too long."
        )

    try:

        decrypted_message = decrypt_message(
            encrypted_message,
            password
        )

        return jsonify({
            "success": True,
            "decrypted_message": decrypted_message
        })

    except Exception:

        return api_error(
            "Decryption failed. Check the encrypted message and password."
        )


# ============================================================
# WEAK CRYPTO DETECTOR
# ============================================================

@main.route("/api/analyze-crypto", methods=["POST"])
def api_analyze_crypto():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    algorithm = data.get(
        "algorithm",
        ""
    )

    if not isinstance(algorithm, str):

        return api_error(
            "Algorithm must be text."
        )

    algorithm = algorithm.strip()

    if not algorithm:

        return api_error(
            "Please provide an algorithm."
        )

    if len(algorithm) > MAX_ALGORITHM_LENGTH:

        return api_error(
            "Algorithm name is too long."
        )

    try:

        result = analyze_crypto_algorithm(
            algorithm
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Unable to analyze the algorithm.",
            500
        )


# ============================================================
# HASH PLAYGROUND
# ============================================================

@main.route("/api/generate-hashes", methods=["POST"])
def api_generate_hashes():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    text = data.get(
        "text",
        ""
    )

    if not isinstance(text, str):

        return api_error(
            "Text must be a string."
        )

    if not text:

        return api_error(
            "Text cannot be empty."
        )

    if len(text) > MAX_TEXT_LENGTH:

        return api_error(
            "Text is too long."
        )

    try:

        result = generate_hashes(
            text
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Hash generation failed.",
            500
        )


# ============================================================
# CAESAR CRYPTANALYSIS
# ============================================================

@main.route("/api/caesar-brute-force", methods=["POST"])
def api_caesar_brute_force():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    ciphertext = data.get(
        "ciphertext",
        ""
    )

    if not isinstance(ciphertext, str):

        return api_error(
            "Ciphertext must be text."
        )

    if not ciphertext:

        return api_error(
            "Ciphertext cannot be empty."
        )

    if len(ciphertext) > MAX_CIPHERTEXT_LENGTH:

        return api_error(
            "Ciphertext is too long."
        )

    try:

        results = caesar_brute_force(
            ciphertext
        )

        return jsonify({
            "success": True,
            "results": results
        })

    except Exception:

        return api_error(
            "Cryptanalysis failed.",
            500
        )


# ============================================================
# SECURITY SCORE
# ============================================================

@main.route("/api/security-score", methods=["POST"])
def api_security_score():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    algorithm = data.get(
        "algorithm",
        "AES-256-GCM"
    )

    key_length = data.get(
        "key_length",
        256
    )

    authentication = data.get(
        "authentication",
        True
    )

    if not isinstance(algorithm, str):

        return api_error(
            "Algorithm must be text."
        )

    algorithm = algorithm.strip()

    if not algorithm:

        return api_error(
            "Algorithm cannot be empty."
        )

    if len(algorithm) > MAX_ALGORITHM_LENGTH:

        return api_error(
            "Algorithm name is too long."
        )

    try:

        key_length = int(
            key_length
        )

    except (ValueError, TypeError):

        return api_error(
            "Key length must be a number."
        )

    if key_length not in ALLOWED_KEY_LENGTHS:

        return api_error(
            "Key length must be 128, 192, or 256 bits."
        )

    if not isinstance(
        authentication,
        bool
    ):

        return api_error(
            "Authentication value must be true or false."
        )

    try:

        result = calculate_security_score(
            algorithm=algorithm,
            key_length=key_length,
            authentication=authentication
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Security score calculation failed.",
            500
        )


# ============================================================
# PASSWORD → KEY DERIVATION
# ============================================================

@main.route("/api/key-derivation", methods=["POST"])
def api_key_derivation():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    password = data.get(
        "password",
        ""
    )

    if not isinstance(password, str):

        return api_error(
            "Password must be text."
        )

    if not password:

        return api_error(
            "Password cannot be empty."
        )

    if len(password) > MAX_PASSWORD_LENGTH:

        return api_error(
            "Password is too long."
        )

    try:

        result = demonstrate_key_derivation(
            password
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Key derivation failed.",
            500
        )


# ============================================================
# PASSWORD ENTROPY
# ============================================================

@main.route("/api/password-entropy", methods=["POST"])
def api_password_entropy():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    password = data.get(
        "password",
        ""
    )

    if not isinstance(password, str):

        return api_error(
            "Password must be text."
        )

    if not password:

        return api_error(
            "Password cannot be empty."
        )

    if len(password) > MAX_PASSWORD_LENGTH:

        return api_error(
            "Password is too long."
        )

    try:

        result = calculate_password_entropy(
            password
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Password entropy calculation failed.",
            500
        )


# ============================================================
# TOY HASH COLLISION LAB
# ============================================================

@main.route("/api/hash-collision", methods=["POST"])
def api_hash_collision():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    text = data.get(
        "text",
        ""
    )

    if not isinstance(text, str):

        return api_error(
            "Text must be a string."
        )

    if not text:

        return api_error(
            "Text cannot be empty."
        )

    if len(text) > MAX_TEXT_LENGTH:

        return api_error(
            "Text is too long."
        )

    try:

        result = find_toy_collision(
            text
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except Exception:

        return api_error(
            "Collision demonstration failed.",
            500
        )


# ============================================================
# SECURITY REPORT
# ============================================================

@main.route("/api/security-report", methods=["POST"])
def api_security_report():

    auth_error = api_login_required()

    if auth_error:
        return auth_error

    data = get_json_data()

    if data is None:

        return api_error(
            "Request must contain valid JSON."
        )

    algorithm = data.get(
        "algorithm",
        "AES-256-GCM"
    )

    key_length = data.get(
        "key_length",
        256
    )

    authentication = data.get(
        "authentication",
        True
    )

    if not isinstance(algorithm, str):

        return api_error(
            "Algorithm must be text."
        )

    algorithm = algorithm.strip()

    if not algorithm:

        return api_error(
            "Algorithm cannot be empty."
        )

    if len(algorithm) > MAX_ALGORITHM_LENGTH:

        return api_error(
            "Algorithm name is too long."
        )

    try:

        key_length = int(
            key_length
        )

    except (ValueError, TypeError):

        return api_error(
            "Key length must be a number."
        )

    if key_length not in ALLOWED_KEY_LENGTHS:

        return api_error(
            "Key length must be 128, 192, or 256 bits."
        )

    if not isinstance(
        authentication,
        bool
    ):

        return api_error(
            "Authentication value must be true or false."
        )

    try:

        report = generate_security_report(
            algorithm=algorithm,
            key_length=key_length,
            authentication=authentication
        )

        return jsonify({
            "success": True,
            "report": report
        })

    except Exception:

        return api_error(
            "Security report generation failed.",
            500
        )