import os
import re
import sys
import logging
import json
from github import Github, GithubException

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Labels related to scakind
SCAKIND_LABELS = ['upgrade-only', 'reachable','ssc']

def extract_ghsa_id_from_filename(filename):
    """
    Extracts the GHSA ID from the filename.
    Supports patterns:
    - GHSA-xxxx-xxxx-xxxx.jsonnet
    - GHSA-xxxx-xxxx-xxxx-SOMETHING.jsonnet
    """
    pattern = r'(GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})'
    match = re.search(pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_field_from_content(file_path, field_name):
    """
    Extracts the value of a specified field from the file content.
    Supports both single and double quotes around field names.
    Example formats:
      scakind='upgrade-only',
      scakind="reachable",
      'scakind': 'upgrade-only',
      "scakind": "reachable",
      scakind: 'upgrade-only',
      scakind: "reachable",
    """
    # Pattern to match field assignments with optional quotes and both ':' and '=' as separators
    pattern = rf"(?<!//\s*)['\"]?{field_name}['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]"
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return None

def validate_scakind(file_path, scakind_value):
    """
    Validates the scakind and the presence/absence of patterns: [] or pattern-sources: [] based on scakind.
    Returns True if valid, False otherwise.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False

    # Define regex patterns with optional quotes and both ':' and '=' separators
    patterns_present = re.search(r'^(?!\s*//).*["\']?patterns["\']?\s*[:=]\s*\[', content, re.IGNORECASE | re.MULTILINE)
    pattern_sources_present = re.search(r'^(?!\s*//).*["\']?pattern-sources["\']?\s*[:=]\s*\[', content, re.IGNORECASE | re.MULTILINE)

    if scakind_value.lower() == 'reachable':
        if not (patterns_present or pattern_sources_present):
            logging.error(f"'scakind' is 'reachable' but neither 'patterns: [' nor 'pattern-sources: [' section is present in file: {file_path}")
            return False
    elif scakind_value.lower() == 'upgrade-only':
        if patterns_present or pattern_sources_present:
            logging.error(f"'scakind' is 'upgrade-only' but either 'patterns: [' or 'pattern-sources: [' section is present in file: {file_path}")
            return False
    else:
        logging.error(f"Invalid 'scakind' value '{scakind_value}' in file: {file_path}. Allowed values are 'upgrade-only' and 'reachable'.")
        return False

    return True

def validate_file(file_path):
    """
    Validates the GHSA ID and scakind in the given file.
    Returns a tuple (is_valid, scakind_value)
    """
    filename = os.path.basename(file_path)
    filename_ghsa = extract_ghsa_id_from_filename(filename)
    if not filename_ghsa:
        logging.error(f"Filename does not contain a valid GHSA ID: {filename}")
        return (False, None)

    file_ghsa = extract_field_from_content(file_path, 'ghsa_id')
    if not file_ghsa:
        logging.error(f"'ghsa_id' not found or invalid format in file: {file_path}")
        return (False, None)

    if filename_ghsa.upper() != file_ghsa.upper():
        logging.error(f"GHSA ID mismatch in file: {file_path}")
        logging.error(f"       Filename GHSA ID: {filename_ghsa}")
        logging.error(f"       File ghsa_id: {file_ghsa}")
        return (False, None)

    # Extract scakind
    scakind = extract_field_from_content(file_path, 'scakind')
    if not scakind:
        logging.error(f"'scakind' not found or invalid format in file: {file_path}")
        return (False, None)

    # Validate scakind and patterns/pattern-sources
    scakind_valid = validate_scakind(file_path, scakind)
    if not scakind_valid:
        return (False, scakind.lower())

    logging.info(f"SUCCESS: GHSA IDs match and 'scakind' is valid for file: {file_path}")
    return (True, scakind.lower())

def get_pr_info():
    """
    Retrieves PR information from environment variables set by GitHub Actions.
    """
    pr_number = os.environ.get('PR_NUMBER')
    repo_owner = os.environ.get('REPO_OWNER')
    repo_name = os.environ.get('REPO_NAME')
    github_token = os.environ.get('GITHUB_TOKEN')

    if not all([pr_number, repo_owner, repo_name, github_token]):
        logging.error("Missing required environment variables for GitHub PR information.")
        sys.exit(1)

    return pr_number, repo_owner, repo_name, github_token

def manage_pr_labels(scakind_values, pr_number, repo_owner, repo_name, github_token):
    """
    Adds labels based on scakind_values and removes existing scakind-related labels.
    """
    g = Github(github_token)
    try:
        repo = g.get_repo(f"{repo_owner}/{repo_name}")
        pr = repo.get_pull(int(pr_number))
    except GithubException as e:
        logging.error(f"GitHub API error: {e}")
        return

    # Remove existing scakind labels
    existing_labels = [label.name for label in pr.get_labels()]
    labels_to_remove = [label for label in existing_labels if label in SCAKIND_LABELS]
    if labels_to_remove:
        try:
            pr.remove_from_labels(*labels_to_remove)
            logging.info(f"Removed labels: {labels_to_remove}")
        except GithubException as e:
            logging.error(f"Error removing labels {labels_to_remove}: {e}")

    # Determine new labels to add
    labels_to_add = [label for label in scakind_values if label in SCAKIND_LABELS]
    labels_to_add.append('ssc')
    if labels_to_add:
        try:
            pr.add_to_labels(*labels_to_add)
            logging.info(f"Added labels: {labels_to_add}")
        except GithubException as e:
            logging.error(f"Error adding labels {labels_to_add}: {e}")

def main():
    if len(sys.argv) < 2:
        print("No files provided for validation.")
        sys.exit(0)  # Exiting without error since no relevant files to validate

    changed_files = sys.argv[1:]
    if not changed_files:
        print("No .jsonnet files provided for validation.")
        sys.exit(0)  # Exiting without error since no relevant files to validate

    all_valid = True
    scakind_values = set()
    for file_path in changed_files:
        if not os.path.isfile(file_path):
            logging.error(f"File does not exist: {file_path}")
            all_valid = False
            continue

        valid, scakind = validate_file(file_path)
        if scakind:
            scakind_values.add(scakind.lower())

        if not valid:
            all_valid = False

    # Output scakind values as JSON for workflow consumption
    scakind_list = list(scakind_values)
    print(json.dumps({"scakind_values": scakind_list}))

    # Manage PR labels based on scakind values
    if scakind_values:
        pr_number, repo_owner, repo_name, github_token = get_pr_info()
        manage_pr_labels(scakind_list, pr_number, repo_owner, repo_name, github_token)

    if all_valid:
        logging.info("All validations passed successfully.")
        sys.exit(0)
    else:
        logging.error("Validation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
