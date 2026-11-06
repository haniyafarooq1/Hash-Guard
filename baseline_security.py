
import os
import hmac
import hashlib
import secrets
import tempfile
from pathlib import Path


# Store the secret key outside the project folder
KEY_FILE = Path.home() / ".hash_guard" / "secret.key"


# 1. Generate or load the secret key
def get_or_create_key():
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)

    if KEY_FILE.exists():
        with open(KEY_FILE, "rb") as file:
            key = file.read()

        if len(key) != 32:
            raise ValueError("Invalid secret key.")

        return key

    key = secrets.token_bytes(32)

    with open(KEY_FILE, "xb") as file:
        file.write(key)

    return key


# 2. Save data safely using a temporary file
def save_atomically(file_path, data):
    temporary_file = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=os.path.dirname(os.path.abspath(file_path)),
            delete=False
        ) as file:
            temporary_file = file.name
            file.write(data)

        os.replace(temporary_file, file_path)

    except OSError:
        if temporary_file and os.path.exists(temporary_file):
            os.remove(temporary_file)
        raise


# 3. Generate an HMAC signature for the baseline
def sign_baseline(baseline_file="baseline.json"):
    try:
        key = get_or_create_key()

        with open(baseline_file, "rb") as file:
            baseline_data = file.read()

        signature = hmac.new(
            key,
            baseline_data,
            hashlib.sha256
        ).hexdigest()

        signature_file = baseline_file + ".sig"

        save_atomically(
            signature_file,
            signature.encode("utf-8")
        )

        print("Baseline signature created successfully!")
        return True

    except (OSError, ValueError) as error:
        print("Could not sign baseline:", error)
        return False


# 4. Verify baseline authenticity
def verify_baseline(baseline_file="baseline.json"):
    try:
        signature_file = baseline_file + ".sig"

        if not KEY_FILE.exists():
            print("Security error: Secret key not found.")
            return False

        key = KEY_FILE.read_bytes()

        if len(key) != 32:
            print("Security error: Invalid secret key.")
            return False

        baseline_data = Path(baseline_file).read_bytes()
        saved_signature = Path(signature_file).read_text(
            encoding="utf-8"
        ).strip()

        expected_signature = hmac.new(
            key,
            baseline_data,
            hashlib.sha256
        ).hexdigest()

        if hmac.compare_digest(saved_signature, expected_signature):
            print("Baseline authenticity verified.")
            return True

        print("SECURITY ALERT: Baseline has been modified!")
        return False

    except FileNotFoundError:
        print("Security error: Baseline or signature file missing.")
        return False

    except (OSError, ValueError) as error:
        print("Could not verify baseline:", error)
        return False
