import base64
import hashlib
import math
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================
# Cryptographic Constants
# ============================================================

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
KDF_ITERATIONS = 600_000


# ============================================================
# Key Derivation
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the user's passphrase
    using PBKDF2-HMAC-SHA256.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("Passphrase cannot be empty.")

    if not isinstance(salt, bytes):
        raise ValueError("Invalid salt.")

    if len(salt) != SALT_LENGTH:
        raise ValueError("Invalid salt length.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


# ============================================================
# AES-256-GCM Encryption
# ============================================================

def encrypt_message(message: str, password: str) -> str:
    """
    Encrypt a message using AES-256-GCM.

    The encrypted package contains:

        salt + nonce + ciphertext

    and is returned as URL-safe Base64.
    """

    if not isinstance(message, str) or not message:
        raise ValueError("Message cannot be empty.")

    if not isinstance(password, str) or not password:
        raise ValueError("Passphrase cannot be empty.")

    # Generate a fresh random salt and nonce
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)

    # Derive AES-256 key
    key = derive_key(password, salt)

    # AES-GCM provides confidentiality and authentication
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode("utf-8"),
        None,
    )

    encrypted_data = (
        salt
        + nonce
        + ciphertext
    )

    return base64.urlsafe_b64encode(
        encrypted_data
    ).decode("utf-8")


# ============================================================
# AES-256-GCM Decryption
# ============================================================

def decrypt_message(
    encrypted_message: str,
    password: str
) -> str:
    """
    Decrypt a CipherVault AES-256-GCM message.
    """

    if not isinstance(encrypted_message, str):
        raise ValueError(
            "Encrypted message must be text."
        )

    if not encrypted_message:
        raise ValueError(
            "Encrypted message cannot be empty."
        )

    if not isinstance(password, str) or not password:
        raise ValueError(
            "Passphrase cannot be empty."
        )

    # Decode and validate Base64
    try:
        encrypted_data = base64.b64decode(
            encrypted_message.encode("utf-8"),
            altchars=b"-_",
            validate=True,
        )
    except Exception as exc:
        raise ValueError(
            "The encrypted message format is invalid."
        ) from exc

    # AES-GCM authentication tag is 16 bytes
    minimum_length = (
        SALT_LENGTH
        + NONCE_LENGTH
        + 16
    )

    if len(encrypted_data) < minimum_length:
        raise ValueError(
            "The encrypted message is incomplete."
        )

    # Extract salt
    salt = encrypted_data[
        :SALT_LENGTH
    ]

    # Extract nonce
    nonce = encrypted_data[
        SALT_LENGTH:
        SALT_LENGTH + NONCE_LENGTH
    ]

    # Extract ciphertext + authentication tag
    ciphertext = encrypted_data[
        SALT_LENGTH + NONCE_LENGTH:
    ]

    # Derive the same AES-256 key
    key = derive_key(
        password,
        salt
    )

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None,
        )
    except Exception as exc:
        raise ValueError(
            "Decryption failed. The passphrase may be "
            "incorrect or the encrypted message may "
            "have been modified."
        ) from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Decryption produced invalid text."
        ) from exc


# ============================================================
# Weak Cryptographic Algorithm Detector
# ============================================================

WEAK_CRYPTO_ALGORITHMS = {
    "md5": {
        "status": "Weak",
        "severity": "high",
        "message": (
            "MD5 is cryptographically broken and should "
            "not be used for security-sensitive applications."
        ),
        "recommendation": (
            "Use SHA-256 or SHA-512 for secure hashing."
        ),
    },

    "sha1": {
        "status": "Weak",
        "severity": "high",
        "message": (
            "SHA-1 has known collision weaknesses and is "
            "deprecated for many security applications."
        ),
        "recommendation": (
            "Use SHA-256 or SHA-512 instead."
        ),
    },

    "des": {
        "status": "Weak",
        "severity": "high",
        "message": (
            "DES uses a key size that is no longer "
            "considered secure against modern attacks."
        ),
        "recommendation": (
            "Use AES-256 instead."
        ),
    },

    "3des": {
        "status": "Deprecated",
        "severity": "medium",
        "message": (
            "3DES has been deprecated for new "
            "security applications."
        ),
        "recommendation": (
            "Use AES-256 instead."
        ),
    },

    "rc4": {
        "status": "Weak",
        "severity": "high",
        "message": (
            "RC4 has multiple known cryptographic weaknesses."
        ),
        "recommendation": (
            "Use AES-GCM instead."
        ),
    },
}


def analyze_crypto_algorithm(
    algorithm: str
) -> dict:
    """
    Analyze a cryptographic algorithm and return
    a simple security assessment.
    """

    if not isinstance(algorithm, str):
        raise ValueError(
            "Algorithm must be text."
        )

    algorithm = algorithm.strip().lower()

    if not algorithm:
        raise ValueError(
            "Please enter a cryptographic algorithm."
        )

    if algorithm in WEAK_CRYPTO_ALGORITHMS:

        result = WEAK_CRYPTO_ALGORITHMS[
            algorithm
        ].copy()

        result["algorithm"] = algorithm.upper()

        return result

    strong_algorithms = {
        "aes-256",
        "aes-256-gcm",
        "sha-256",
        "sha-512",
    }

    if algorithm in strong_algorithms:

        return {
            "algorithm": algorithm.upper(),
            "status": "Strong",
            "severity": "low",
            "message": (
                "This algorithm is generally considered "
                "suitable for modern security applications "
                "when implemented correctly."
            ),
            "recommendation": (
                "Continue using secure key management "
                "and proper implementation practices."
            ),
        }

    return {
        "algorithm": algorithm.upper(),
        "status": "Unknown",
        "severity": "medium",
        "message": (
            "CipherVault does not have a predefined "
            "security assessment for this algorithm."
        ),
        "recommendation": (
            "Verify the algorithm against current "
            "cryptographic standards before using it."
        ),
    }


# ============================================================
# Hash Playground
# ============================================================

def generate_hashes(text: str) -> dict:
    """
    Generate SHA-256 and SHA-512 hashes
    for the supplied text.
    """

    if not isinstance(text, str) or not text:
        raise ValueError(
            "Text cannot be empty."
        )

    encoded_text = text.encode("utf-8")

    sha256_hash = hashlib.sha256(
        encoded_text
    ).hexdigest()

    sha512_hash = hashlib.sha512(
        encoded_text
    ).hexdigest()

    return {
        "sha256": sha256_hash,
        "sha512": sha512_hash,
        "input_length": len(text),
        "sha256_length": len(sha256_hash),
        "sha512_length": len(sha512_hash),
    }


# ============================================================
# Caesar Cipher
# ============================================================

def caesar_decrypt(
    text: str,
    shift: int
) -> str:
    """
    Decrypt text using a Caesar cipher shift.
    """

    if not isinstance(text, str):
        raise ValueError(
            "Text must be a string."
        )

    if not isinstance(shift, int):
        raise ValueError(
            "Shift must be an integer."
        )

    result = []

    for char in text:

        if char.isupper():

            decrypted = chr(
                (
                    ord(char)
                    - ord("A")
                    - shift
                ) % 26
                + ord("A")
            )

            result.append(decrypted)

        elif char.islower():

            decrypted = chr(
                (
                    ord(char)
                    - ord("a")
                    - shift
                ) % 26
                + ord("a")
            )

            result.append(decrypted)

        else:

            result.append(char)

    return "".join(result)


def caesar_brute_force(
    text: str
) -> list:
    """
    Try all possible Caesar cipher shifts.
    """

    if not isinstance(text, str):
        raise ValueError(
            "Ciphertext must be text."
        )

    if not text.strip():
        raise ValueError(
            "Ciphertext cannot be empty."
        )

    results = []

    for shift in range(1, 26):

        plaintext = caesar_decrypt(
            text,
            shift
        )

        results.append({
            "shift": shift,
            "plaintext": plaintext
        })

    return results


# ============================================================
# Educational Cryptographic Security Score
# ============================================================

def calculate_security_score(
    algorithm: str,
    key_length: int = 256,
    authentication: bool = True
) -> dict:
    """
    Calculate an educational cryptographic
    security score.

    This is a rule-based heuristic and is NOT
    a security certification.
    """

    if not isinstance(algorithm, str):
        raise ValueError(
            "Algorithm must be text."
        )

    algorithm = algorithm.strip().lower()

    if not algorithm:
        raise ValueError(
            "Please enter a cryptographic algorithm."
        )

    if not isinstance(key_length, int):
        raise ValueError(
            "Key length must be an integer."
        )

    if key_length < 0:
        raise ValueError(
            "Key length cannot be negative."
        )

    if not isinstance(authentication, bool):
        raise ValueError(
            "Authentication value must be boolean."
        )

    score = 100
    findings = []

    weak_algorithms = {
        "md5": 40,
        "sha1": 40,
        "des": 35,
        "3des": 50,
        "rc4": 30,
    }

    if algorithm in weak_algorithms:

        score -= weak_algorithms[
            algorithm
        ]

        findings.append(
            f"{algorithm.upper()} is considered "
            "weak or deprecated."
        )

    elif algorithm in {
        "aes-256",
        "aes-256-gcm",
        "sha-256",
        "sha-512",
    }:

        findings.append(
            f"{algorithm.upper()} is suitable for "
            "modern applications when implemented correctly."
        )

    else:

        score -= 15

        findings.append(
            "Algorithm security could not be fully assessed."
        )

    if key_length < 128:

        score -= 20

        findings.append(
            "Key length is below the recommended minimum."
        )

    elif key_length < 256:

        score -= 5

        findings.append(
            "Consider using a 256-bit key where appropriate."
        )

    if not authentication:

        score -= 15

        findings.append(
            "Authenticated encryption is not enabled."
        )

    score = max(
        0,
        min(score, 100)
    )

    if score >= 80:
        rating = "Strong"

    elif score >= 60:
        rating = "Moderate"

    elif score >= 40:
        rating = "Weak"

    else:
        rating = "Critical"

    return {
        "score": score,
        "rating": rating,
        "algorithm": algorithm.upper(),
        "findings": findings,
        "note": (
            "This score is an educational rule-based "
            "heuristic and is not an industry "
            "security certification."
        ),
    }


# ============================================================
# Password → Key Demonstrator
# ============================================================

def demonstrate_key_derivation(
    password: str
) -> dict:
    """
    Demonstrate the password-to-key derivation process
    without exposing the complete derived key.
    """

    if not isinstance(password, str) or not password:
        raise ValueError(
            "Password cannot be empty."
        )

    salt = os.urandom(
        SALT_LENGTH
    )

    key = derive_key(
        password,
        salt
    )

    return {
        "password_length": len(password),
        "salt_length": len(salt),
        "key_length": len(key) * 8,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": KDF_ITERATIONS,
        "algorithm": "AES-256-GCM",
        "salt": base64.urlsafe_b64encode(
            salt
        ).decode("utf-8"),
        "key_preview": (
            key.hex()[:8]
            + "..."
            + key.hex()[-8:]
        ),
    }


# ============================================================
# Password Entropy Demonstrator
# ============================================================

def calculate_password_entropy(
    password: str
) -> dict:
    """
    Calculate theoretical password entropy based on
    character-set size and password length.

    This is an educational estimate and is NOT a
    complete password-strength assessment.
    """

    if not isinstance(password, str) or not password:
        raise ValueError(
            "Password cannot be empty."
        )

    charset_size = 0
    categories = []

    if any(
        char.islower()
        for char in password
    ):

        charset_size += 26
        categories.append("Lowercase")

    if any(
        char.isupper()
        for char in password
    ):

        charset_size += 26
        categories.append("Uppercase")

    if any(
        char.isdigit()
        for char in password
    ):

        charset_size += 10
        categories.append("Numbers")

    if any(
        not char.isalnum()
        for char in password
    ):

        charset_size += 33
        categories.append("Symbols")

    length = len(password)

    entropy = (
        length
        * math.log2(charset_size)
    )

    return {
        "length": length,
        "charset_size": charset_size,
        "entropy": round(
            entropy,
            2
        ),
        "categories": categories,
        "note": (
            "This is a theoretical entropy estimate. "
            "It does not account for common passwords, "
            "patterns, leaked credentials, or human behavior."
        ),
    }


# ============================================================
# Educational Toy Hash
# ============================================================

def toy_hash(text: str) -> str:
    """
    Educational toy hash with a very small output space.

    This is intentionally NOT cryptographically secure.
    It produces only 256 possible hash values.
    """

    if not isinstance(text, str) or not text:
        raise ValueError(
            "Text cannot be empty."
        )

    value = sum(
        ord(char)
        for char in text
    ) % 256

    return f"{value:02x}"


def find_toy_collision(
    text: str
) -> dict:
    """
    Demonstrate a collision in the intentionally
    weak toy hash.

    The function creates a different input whose
    additional characters contribute 256 to the
    hash calculation.

    Since 256 % 256 == 0, both inputs produce
    the same hash.
    """

    if not isinstance(text, str) or not text:
        raise ValueError(
            "Text cannot be empty."
        )

    original_hash = toy_hash(text)

    # Unicode code points:
    #
    # '!' = 33
    # 'ß' = 223
    #
    # 33 + 223 = 256
    #
    # 256 % 256 = 0
    #
    # Therefore adding "!ß" does not change
    # the final toy hash value.

    collision_text = (
        text + "!ß"
    )

    collision_hash = toy_hash(
        collision_text
    )

    return {
        "found": True,
        "original": text,
        "original_hash": original_hash,
        "collision": collision_text,
        "collision_hash": collision_hash,
    }


# ============================================================
# Security Report Generator
# ============================================================

def generate_security_report(
    algorithm: str,
    key_length: int = 256,
    authentication: bool = True
) -> dict:
    """
    Generate an educational cryptographic
    security assessment report.
    """

    result = calculate_security_score(
        algorithm=algorithm,
        key_length=key_length,
        authentication=authentication
    )

    report = {
        "title": (
            "CipherVault Cryptographic Security Report"
        ),
        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "algorithm": result["algorithm"],
        "key_length": key_length,
        "authenticated_encryption": (
            "Enabled"
            if authentication
            else "Disabled"
        ),
        "security_score": result["score"],
        "rating": result["rating"],
        "findings": result["findings"],
        "note": result["note"],
    }

    return report