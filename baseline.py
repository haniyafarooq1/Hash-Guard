
import os
import hashlib
import json
import tempfile


# 1. Find all files inside a folder and its subfolders
def get_files(folder_path):
    files = []

    for root, directories, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            files.append(file_path)

    return files


# 2. Calculate SHA-256 hash of a file
def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# 3. Build a baseline without saving it yet
def build_baseline(folder_path):
    if not os.path.isdir(folder_path):
        print("Error: Invalid folder path.")
        return None

    baseline = {}
    failed_files = []

    for file_path in get_files(folder_path):
        try:
            file_hash = calculate_hash(file_path)
            relative_path = os.path.relpath(file_path, folder_path)
            baseline[relative_path] = file_hash

        except (PermissionError, OSError):
            failed_files.append(file_path)

    # Do not save an incomplete baseline
    if failed_files:
        print("Error: Some files could not be accessed.")
        print("Baseline was not saved.")
        for file_path in failed_files:
            print(file_path)
        return None

    return baseline


# 4. Create and safely save a baseline
def create_baseline(folder_path, baseline_file="baseline.json"):
    baseline = build_baseline(folder_path)

    if baseline is None:
        return False

    temporary_file = None

    try:
        # Create temporary file in the same folder
        target_folder = os.path.dirname(os.path.abspath(baseline_file))

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_folder,
            delete=False
        ) as file:
            temporary_file = file.name
            json.dump(baseline, file, indent=4)

        # Replace old baseline only after successful saving
        os.replace(temporary_file, baseline_file)

        print("Baseline created successfully!")
        print("Total files saved:", len(baseline))
        return True

    except OSError as error:
        print("Error: Could not save baseline:", error)

        if temporary_file and os.path.exists(temporary_file):
            os.remove(temporary_file)

        return False


# 5. Load and validate an existing baseline
def load_baseline(baseline_file="baseline.json"):
    try:
        with open(baseline_file, "r", encoding="utf-8") as file:
            baseline = json.load(file)

        if not isinstance(baseline, dict):
            print("Invalid baseline format.")
            return {}

        for path, file_hash in baseline.items():
            if not isinstance(path, str) or not isinstance(file_hash, str):
                print("Invalid baseline data.")
                return {}

            if len(file_hash) != 64 or any(
                character not in "0123456789abcdef"
                for character in file_hash.lower()
            ):
                print("Invalid SHA-256 hash in baseline.")
                return {}

        return baseline

    except FileNotFoundError:
        print("Baseline file not found.")
        return {}

    except json.JSONDecodeError:
        print("Baseline file is corrupted.")
        return {}

    except OSError as error:
        print("Could not read baseline:", error)
        return {}


# 6. Intentionally update the baseline
def update_baseline(folder_path, baseline_file="baseline.json"):
    print("Updating baseline...")

    success = create_baseline(folder_path, baseline_file)

    if success:
        print("Baseline updated successfully!")

    return success
