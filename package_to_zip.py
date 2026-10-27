"""
PhishShift Project Packaging Utility
Compresses the entire PhishShift project into a clean .zip archive
ready for submission, sharing, and deployment.
"""
import os
import zipfile
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZIP_NAME = "phishshift_project.zip"
OUTPUT_ZIP_PATH = os.path.join(BASE_DIR, ZIP_NAME)

# Files and directories to exclude from the zip
EXCLUDES = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".vscode",
    ".idea",
    "test.txt",
    ZIP_NAME
}


def make_project_zip():
    print(f"[*] Packaging PhishShift project into: {OUTPUT_ZIP_PATH}")
    total_files = 0

    with zipfile.ZipFile(OUTPUT_ZIP_PATH, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(BASE_DIR):
            # Exclude unwanted directories
            dirs[:] = [d for d in dirs if d not in EXCLUDES and not d.endswith(".pyc")]

            for file in files:
                if file in EXCLUDES or file.endswith(".pyc"):
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, os.path.dirname(BASE_DIR))
                zipf.write(full_path, arcname=rel_path)
                total_files += 1

    size_kb = os.path.getsize(OUTPUT_ZIP_PATH) / 1024
    print(f"[✓] Successfully generated {ZIP_NAME} ({total_files} files, {size_kb:.1f} KB)")
    print(f"[+] Zip file location: {OUTPUT_ZIP_PATH}")

    # Also copy to user Desktop if accessible for convenient 1-click access
    try:
        user_home = os.path.expanduser("~")
        desktop_dir = os.path.join(user_home, "Desktop")
        if os.path.exists(desktop_dir):
            dest = os.path.join(desktop_dir, ZIP_NAME)
            shutil.copy2(OUTPUT_ZIP_PATH, dest)
            print(f"[+] Also copied convenient ZIP to your Desktop: {dest}")
    except Exception as e:
        pass


if __name__ == "__main__":
    make_project_zip()
