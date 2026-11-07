import os
from pathlib import Path
from datetime import datetime
from baseline import load_baseline, calculate_hash


def create_result(folder_path):
    return {
        "status": "not_started",
        "scan_time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "directory": str(Path(folder_path).resolve()),
        "summary": { "modified": 0, "added": 0, "deleted": 0, "renamed": 0, "errors": 0},
        "modified": [],
        "added": [],
        "deleted": [],
        "renamed": [],
        "errors": []
    }


def is_same_file(path1, path2):
    try:
        return Path(path1).resolve() == Path(path2).resolve()
    except OSError:
        return False


def is_inside_directory(path, directory):
    try:
        Path(path).resolve().relative_to(Path(directory).resolve())
        return True
    except (ValueError, OSError):
        return False


def check_integrity(folder_path, baseline_file="baseline.json"):

    result = create_result(folder_path)

    if not os.path.isdir(folder_path):
        result["status"] = "invalid_directory"
        result["errors"].append({"path": str(folder_path), "message": "Invalid or unavailable monitoring directory."})
        result["summary"]["errors"] = 1
        return result

    root_folder = Path(folder_path).resolve()
    baseline_path = Path(baseline_file).resolve()

    baseline = load_baseline(str(baseline_path))

    if not baseline:
        result["status"] = "baseline_unavailable"
        result["errors"].append({"path": str(baseline_path), "message": "Baseline unavailable or authentication failed."})
        result["summary"]["errors"] = 1
        return result

    current_files = {}
    inaccessible_paths = []

    def handle_walk_error(error):
        error_path = error.filename

        if error_path is None:
            error_path = str(root_folder)

        inaccessible_paths.append(str(Path(error_path).resolve()))
        result["errors"].append({"path": str(error_path), "message": str(error)})

    signature_path = Path(str(baseline_path) + ".sig")

    for root, directories, filenames in os.walk(root_folder, onerror=handle_walk_error):

        for filename in filenames:
            file_path = Path(root) / filename

            if is_same_file(file_path, baseline_path):
                continue

            if is_same_file(file_path, signature_path):
                continue

            relative_path = os.path.relpath(file_path, root_folder)

            try:
                file_hash = calculate_hash(file_path)
                current_files[relative_path] = file_hash

            except (PermissionError, OSError) as error:
                inaccessible_paths.append(str(file_path.resolve()))
                result["errors"].append({"path": str(file_path), "message": str(error)})

    for relative_path, old_hash in baseline.items():

        if relative_path in current_files:

            new_hash = current_files[relative_path]

            if old_hash != new_hash:
                result["modified"].append({"path": relative_path, "baseline_hash": old_hash, "current_hash": new_hash})

        else:
            original_path = root_folder / relative_path
            inaccessible = False

            for inaccessible_path in inaccessible_paths:
                if (is_same_file(original_path, inaccessible_path) or is_inside_directory(original_path, inaccessible_path)):
                    inaccessible = True
                    break

            if not inaccessible:
                result["deleted"].append({"path": relative_path, "baseline_hash": old_hash})

    for relative_path, current_hash in current_files.items():

        if relative_path not in baseline:
            result["added"].append({"path": relative_path, "current_hash": current_hash})


    added_by_hash = {}

    for added_file in result["added"]:
        file_hash = added_file["current_hash"]

        if file_hash not in added_by_hash:
            added_by_hash[file_hash] = []

        added_by_hash[file_hash].append(added_file)

    remaining_deleted = []

    for deleted_file in result["deleted"]:

        old_hash = deleted_file["baseline_hash"]

        if (old_hash in added_by_hash and len(added_by_hash[old_hash]) > 0):

            matching_file = added_by_hash[old_hash].pop(0)
            result["renamed"].append({"old_path": deleted_file["path"], "new_path": matching_file["path"], "sha256": old_hash})

        else:
            remaining_deleted.append(deleted_file)

    renamed_paths = []

    for rename in result["renamed"]:
        renamed_paths.append(rename["new_path"])

    remaining_added = []

    for added_file in result["added"]:
        if added_file["path"] not in renamed_paths:
            remaining_added.append(added_file)

    result["deleted"] = remaining_deleted
    result["added"] = remaining_added

    result["summary"]["modified"] = len(result["modified"])
    result["summary"]["added"] = len(result["added"])
    result["summary"]["deleted"] = len(result["deleted"])
    result["summary"]["renamed"] = len(result["renamed"])
    result["summary"]["errors"] = len(result["errors"])

    if result["errors"]:
        result["status"] = "completed_with_errors"
    else:
        result["status"] = "success"

    return result


if __name__ == "__main__":

    folder = input("Enter the folder to monitor: ")
    baseline_file = input("Enter baseline file path (default: baseline.json): ")

    if not baseline_file:
        baseline_file = "baseline.json"

    scan_result = check_integrity(folder, baseline_file)

    print("\nIntegrity Checks Results")
    print("Status:", scan_result["status"])
    print("Scan time:", scan_result["scan_time"])

    print("\nSummary:")

    for change_type, count in scan_result["summary"].items():
        print(change_type, ":", count)

    print("\nModified files:", scan_result["modified"])
    print("\nAdded files:", scan_result["added"])
    print("\nDeleted files:", scan_result["deleted"])
    print("\nRenamed files:", scan_result["renamed"])
    print("\nErrors:", scan_result["errors"])
