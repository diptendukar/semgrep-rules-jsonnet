import os
import re
import sys

def extract_ghsa_id_from_filename(filename):

    pattern = r'(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})'
    match = re.search(pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_ghsa_id_from_content(file_path):

    pattern = r"ghsa_id\s*=\s*'([^']+)'"
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None

def validate_file(file_path):
    filename = os.path.basename(file_path)
    filename_ghsa = extract_ghsa_id_from_filename(filename)
    if not filename_ghsa:
        print(f"ERROR: Filename does not contain a valid GHSA ID: {filename}")
        return False

    file_ghsa = extract_ghsa_id_from_content(file_path)
    if not file_ghsa:
        print(f"ERROR: ghsa_id not found or invalid format in file: {file_path}")
        return False

    if filename_ghsa.lower() != file_ghsa.lower():
        print(f"ERROR: GHSA ID mismatch in file: {file_path}")
        print(f"       Filename GHSA ID: {filename_ghsa}")
        print(f"       File ghsa_id: {file_ghsa}")
        return False

    print(f"SUCCESS: GHSA IDs match for file: {file_path}")
    return True

def main():
    if len(sys.argv) < 2:
        print("No files provided for validation.")
        sys.exit(0)  # Exiting without error since no relevant files to validate

    changed_files = sys.argv[1:]
    if not changed_files:
        print("No .jsonnet files provided for validation.")
        sys.exit(0)  # Exiting without error since no relevant files to validate

    all_valid = True
    for file_path in changed_files:
        if not os.path.isfile(file_path):
            print(f"ERROR: File does not exist: {file_path}")
            all_valid = False
            continue

        valid = validate_file(file_path)
        if not valid:
            all_valid = False

    if all_valid:
        print("All GHSA IDs are valid and consistent.")
        sys.exit(0)
    else:
        print("GHSA ID validation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
