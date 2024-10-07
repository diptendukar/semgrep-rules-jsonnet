import os
import re
import sys

SCAKIND_LABELS = ['upgrade-only', 'reachable']


def get_pr_info():
    """
    Retrieves PR information from environment variables set by GitHub Actions.
    """
    pr_number = os.environ.get('PR_NUMBER')
    repo_owner = os.environ.get('REPO_OWNER')
    repo_name = os.environ.get('REPO_NAME')
    github_token = os.environ.get('GITHUB_TOKEN')

    if not all([pr_number, repo_owner, repo_name, github_token]):
        print("Missing required environment variables for GitHub PR information.")
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
        print(f"GitHub API error: {e}")
        return

    # Remove existing scakind labels
    existing_labels = [label.name for label in pr.get_labels()]
    labels_to_remove = [label for label in existing_labels if label in SCAKIND_LABELS]
    if labels_to_remove:
        try:
            pr.remove_from_labels(*labels_to_remove)
            print(f"Removed labels: {labels_to_remove}")
        except GithubException as e:
            print(f"Error removing labels {labels_to_remove}: {e}")

    # Determine new labels to add
    labels_to_add = [label for label in scakind_values if label in SCAKIND_LABELS]
    if labels_to_add:
        try:
            pr.add_to_labels('ssc')
            pr.add_to_labels(*labels_to_add)
            print(f"Added labels: {labels_to_add}")
        except GithubException as e:
            print(f"Error adding labels {labels_to_add}: {e}")

def extract_ghsa_id_from_filename(filename):
    pattern = r"(GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})"
    match = re.search(pattern, filename, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def extract_field_from_content(file_path, field_name):
    # Pattern to match field assignments with single or double quotes
    pattern = rf"{field_name}\s*=\s*['\"]([^'\"]+)['\"]"
    try:
        with open(file_path) as f:
            content = f.read()
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
    return None


def validate_scakind(file_path, scakind_value):
    """
    Validates the scakind and the presence/absence of patterns: [] or pattern-sources: [] based on scakind.
    """
    try:
        with open(file_path) as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False

    # Define the expected behavior based on scakind
    if scakind_value.lower() == "reachable":
        # Must contain either patterns: [ or pattern-sources: [
        # Adjusted regex to include optional quotes around field names
        patterns_present = re.search(
            r'^(?!\s*//).*["\']?patterns["\']?\s*:\s*\[',
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        pattern_sources_present = re.search(
            r'^(?!\s*//).*["\']?pattern-sources["\']?\s*:\s*\[',
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        if not (patterns_present or pattern_sources_present):
            print(
                f"ERROR: 'scakind' is 'reachable' but neither 'patterns: [' nor 'pattern-sources: [' section is present in file: {file_path}"
            )
            return False
    elif scakind_value.lower() == "upgrade-only":
        # Must NOT contain either patterns: [ or pattern-sources: [
        patterns_present = re.search(
            r'^(?!\s*//).*["\']?patterns["\']?\s*:\s*\[',
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        pattern_sources_present = re.search(
            r'^(?!\s*//).*["\']?pattern-sources["\']?\s*:\s*\[',
            content,
            re.IGNORECASE | re.MULTILINE,
        )
        if patterns_present or pattern_sources_present:
            print(
                f"ERROR: 'scakind' is 'upgrade-only' but either 'patterns: [' or 'pattern-sources: [' section is present in file: {file_path}"
            )
            return False
    else:
        print(
            f"ERROR: Invalid 'scakind' value '{scakind_value}' in file: {file_path}. Allowed values are 'upgrade-only' and 'reachable'."
        )
        return False
    return True


def validate_file(file_path):
    filename = os.path.basename(file_path)
    filename_ghsa = extract_ghsa_id_from_filename(filename)
    if not filename_ghsa:
        print(f"ERROR: Filename does not contain a valid GHSA ID: {filename}")
        return (False, None)

    file_ghsa = extract_field_from_content(file_path, "ghsa_id")
    if not file_ghsa:
        print(f"ERROR: 'ghsa_id' not found or invalid format in file: {file_path}")
        return (False, None)

    if filename_ghsa.lower() != file_ghsa.lower():
        print(f"ERROR: GHSA ID mismatch in file: {file_path}")
        print(f"       Filename GHSA ID: {filename_ghsa}")
        print(f"       File ghsa_id: {file_ghsa}")
        return (False, None)

    scakind = extract_field_from_content(file_path, "scakind")
    if not scakind:
        print(f"ERROR: 'scakind' not found or invalid format in file: {file_path}")
        return (False, None)

    scakind_valid = validate_scakind(file_path, scakind)
    if not scakind_valid:
        return (False, scakind.lower())

    print(f"SUCCESS: GHSA IDs match and 'scakind' is valid for file: {file_path}")
    return (True, scakind.lower())


def main():
    if len(sys.argv) < 2:
        print("No files provided for validation.")
        sys.exit(0)

    changed_files = sys.argv[1:]
    if not changed_files:
        print("No .jsonnet files provided for validation.")
        sys.exit(0)

    all_valid = True
    scakind_values = set()

    for file_path in changed_files:
        if not os.path.isfile(file_path):
            print(f"ERROR: File does not exist: {file_path}")
            all_valid = False
            continue

        valid,scakind = validate_file(file_path)
        if scakind:
            scakind_values.add(scakind.lower())

        if not valid:
            all_valid = False

    scakind_list = list(scakind_values)
    print(scakind_list)

    # Manage PR labels based on scakind values
    if scakind_values:
        pr_number, repo_owner, repo_name, github_token = get_pr_info()
        manage_pr_labels(scakind_list, pr_number, repo_owner, repo_name, github_token)

    if all_valid:
        print("All validations passed successfully.")
        sys.exit(0)
    else:
        print("Validation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()