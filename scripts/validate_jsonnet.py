import os
import re
import sys

def extract_ghsa_id_from_filename(filename):

    pattern = r'(GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})'
    match = re.search(pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_field_from_content(file_path, field_name):

    # Pattern to match field assignments with single or double quotes
    pattern = rf"{field_name}\s*=\s*['\"]([^'\"]+)['\"]"
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None

def validate_scakind(file_path, scakind_value):

    if scakind_value.lower() == 'reachable':
        # Must contain patterns: [
        patterns_present = re.search(r'patterns\s*:\s*\[', open(file_path).read(), re.IGNORECASE)
        if not patterns_present:
            print(f"ERROR: 'scakind' is 'reachable' but 'patterns: [' section is missing in file: {file_path}")
            return False
    elif scakind_value.lower() == 'upgrade-only':
        # Must NOT contain patterns: [
        patterns_present = re.search(r'patterns\s*:\s*\[', open(file_path).read(), re.IGNORECASE)
        if patterns_present:
            print(f"ERROR: 'scakind' is 'upgrade-only' but 'patterns: [' section is present in file: {file_path}")
            return False
    else:
        print(f"ERROR: Invalid 'scakind' value '{scakind_value}' in file: {file_path}. Allowed values are 'upgrade-only' and 'reachable'.")
        return False
    return True

def validate_file(file_path):

    filename = os.path.basename(file_path)
    filename_ghsa = extract_ghsa_id_from_filename(filename)
    if not filename_ghsa:
        print(f"ERROR: Filename does not contain a valid GHSA ID: {filename}")
        return False

    file_ghsa = extract_field_from_content(file_path, 'ghsa_id')
    if not file_ghsa:
        print(f"ERROR: 'ghsa_id' not found or invalid format in file: {file_path}")
        return False

    if filename_ghsa.upper() != file_ghsa.upper():
        print(f"ERROR: GHSA ID mismatch in file: {file_path}")
        print(f"       Filename GHSA ID: {filename_ghsa}")
        print(f"       File ghsa_id: {file_ghsa}")
        return False


    scakind = extract_field_from_content(file_path, 'scakind')
    if not scakind:
        print(f"ERROR: 'scakind' not found or invalid format in file: {file_path}")
        return False


    scakind_valid = validate_scakind(file_path, scakind)
    if not scakind_valid:
        return False

    print(f"SUCCESS: GHSA IDs match and 'scakind' is valid for file: {file_path}")
    return True

def main():
    if len(sys.argv) < 2:
        print("No files provided for validation.")
        sys.exit(0)  

    changed_files = sys.argv[1:]
    if not changed_files:
        print("No .jsonnet files provided for validation.")
        sys.exit(0)  

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
        print("All validations passed successfully.")
        sys.exit(0)
    else:
        print("Validation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
