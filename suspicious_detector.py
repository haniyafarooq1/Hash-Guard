
import os
import stat
from pathlib import Path
from datetime import datetime

RISKY_EXTENSIONS = {".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".psm1", ".vbs",
    ".vbe", ".js", ".jse", ".hta", ".reg", ".sh"}

EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1",".psm1", ".vbs", ".vbe", ".sh"}

def create_result(folder_path):

    return {"status": "not_started", "scan_time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "directory": str(Path(folder_path).resolve()),
        "summary": {"suspicious_files": 0, "newly_added_files": 0, "executable_files": 0, "errors": 0},
        "suspicious_files": [],
        "newly_added_files": [],
        "executable_files": [],
        "errors": []
    }


def is_executable_file(file_path):
    extension = Path(file_path).suffix.lower()

    if extension in EXECUTABLE_EXTENSIONS:
        return True

    try:
        file_mode = os.stat(file_path).st_mode
        if file_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            return True

    except OSError:
        pass

    return False


def check_suspicious_files(folder_path, integrity_result=None):

    result = create_result(folder_path)

    if not os.path.isdir(folder_path):
        result["status"] = "invalid_directory"
        result["errors"].append({"path": str(folder_path), "message": "Invalid or unavailable monitoring directory."})
        result["summary"]["errors"] = 1
        return result

    root_folder = Path(folder_path).resolve()

    newly_added_paths = set()

    if integrity_result is not None:

        for added_file in integrity_result.get("added", []):

            if isinstance(added_file, dict) and "path" in added_file:
                relative_path = added_file["path"]
                newly_added_paths.add(os.path.normcase(os.path.normpath(relative_path)))

    def handle_walk_error(error):

        error_path = error.filename

        if error_path is None:
            error_path = str(root_folder)

        result["errors"].append({"path": str(error_path), "message": str(error)})

    for root, directories, filenames in os.walk(root_folder, onerror=handle_walk_error):

        for filename in filenames:

            file_path = Path(root) / filename
            relative_path = os.path.relpath(file_path, root_folder)
            extension = file_path.suffix.lower()

            reasons = []
            if extension in RISKY_EXTENSIONS:
                reasons.append("File has a potentially risky extension.")

            try:
                executable = is_executable_file(file_path)

                if executable:
                    result["executable_files"].append({"path": relative_path, "extension": extension})
                    reasons.append("File is executable or has an executable file type.")

            except OSError as error:
                result["errors"].append({"path": str(file_path), "message": str(error)})
                continue

            normalized_path = os.path.normcase(os.path.normpath(relative_path))

            if normalized_path in newly_added_paths:
                result["newly_added_files"].append({"path": relative_path, "reason": "File was not present in the authenticated baseline."})
                reasons.append("File was newly added after baseline creation.")

            if reasons:
                result["suspicious_files"].append({ "path": relative_path, "extension": extension, "reasons": reasons,
                    "severity": "high" if executable else "medium"})

    result["summary"]["suspicious_files"] = len(result["suspicious_files"])
    result["summary"]["newly_added_files"] = len(result["newly_added_files"])
    result["summary"]["executable_files"] = len(result["executable_files"])
    result["summary"]["errors"] = len(result["errors"])

    if result["errors"]:
        result["status"] = "completed_with_errors"
    else:
        result["status"] = "success"

    return result


if __name__ == "__main__":

    folder = input("Enter the folder to scan: ")
    scan_result = check_suspicious_files(folder)

    print("\nSuspicious File Detection Results")
    print("Status:", scan_result["status"])
    print("Scan time:", scan_result["scan_time"])
    print("\nSummary:")

    for finding, count in scan_result["summary"].items():
        print(finding, ":", count)

    print("\nSuspicious files:")
    for file in scan_result["suspicious_files"]:
        print(file)

    print("\nNewly added files:")
    for file in scan_result["newly_added_files"]:
        print(file)

    print("\nExecutable files:")
    for file in scan_result["executable_files"]:
        print(file)

    print("\nErrors:")
    for error in scan_result["errors"]:
        print(error)
