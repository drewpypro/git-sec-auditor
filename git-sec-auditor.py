#!/usr/bin/env python3
import os
import csv
import re
import json
import argparse
import logging
import requests
import time
from datetime import datetime
from git import Repo

# Add sanitization function to clean tokens from logs
def sanitize_token(message):
    """Remove sensitive tokens from log messages."""
    if not isinstance(message, str):
        message = str(message)
    
    # Remove tokens from URLs
    message = re.sub(r'https://[^:@\s]+:[^:@\s]+@', 'https://[REDACTED]@', message)
    
    # Remove GitHub tokens
    message = re.sub(r'github_pat_[A-Za-z0-9_]+', '[REDACTED_TOKEN]', message)
    message = re.sub(r'ghp_[A-Za-z0-9]{36,}', '[REDACTED_TOKEN]', message)
    message = re.sub(r'gho_[A-Za-z0-9]{36,}', '[REDACTED_TOKEN]', message)
    message = re.sub(r'ghu_[A-Za-z0-9]{36,}', '[REDACTED_TOKEN]', message)
    message = re.sub(r'ghs_[A-Za-z0-9]{36,}', '[REDACTED_TOKEN]', message)
    
    # Remove authentication headers
    message = re.sub(r'Authorization: token [^"\'\s\)]+', 'Authorization: token [REDACTED]', message)
    message = re.sub(r'token [A-Za-z0-9_\-\.]{35,}', 'token [REDACTED]', message)
    
    return message

# Create a filter for log records
class TokenFilter(logging.Filter):
    """Filter to remove sensitive tokens from log records."""
    
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = sanitize_token(record.msg)
        if hasattr(record, 'args') and record.args:
            args = list(record.args)
            for i, arg in enumerate(args):
                if isinstance(arg, str):
                    args[i] = sanitize_token(arg)
            record.args = tuple(args)
        return True

# Set up logging with sanitization
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("git_audit.log"),
        logging.StreamHandler()
    ]
)

# Add filter to the root logger
for handler in logging.root.handlers:
    handler.addFilter(TokenFilter())

# Configure error logger with sanitization
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_file_handler = logging.FileHandler("errors.txt")
error_file_handler.setLevel(logging.ERROR)
error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_file_handler.addFilter(TokenFilter())
error_logger.addHandler(error_file_handler)

# Disable Git logger to prevent token leakage
logging.getLogger('git').setLevel(logging.WARNING)

BASE_DIR = "cloned_repos"

# Default patterns (can be overridden via config file)
DEFAULT_PATTERNS = {
    "network_security": {
        "name": "Network Security",
        "patterns": [
            "aws_security_group", "aws_route", "gateway", "subnet", 
            "prefix", "endpoint", "rule", "eip", "load", "public"
        ]
    },
    "iam": {
        "name": "IAM",
        "patterns": [
            "aws_iam", "role", "policy", "permission", "user", "group"
        ]
    },
    "network": {
        "name": "Network",
        "patterns": [
            "vpc", "subnet", "route", "gateway", "load"
        ]
    }
}

# Default approvers (can be overridden via config file)
DEFAULT_APPROVERS = {
    "network_security": ["drewpypro"],
    "iam": ["realoksi"],
    "network": ["blahsadfawerwa3r23rwerwe"]
}

class RateLimitExceeded(Exception):
    """Exception raised when GitHub API rate limit is exceeded."""
    pass

def load_config(config_file):
    """Load configuration from JSON file."""
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    return {
        "patterns": DEFAULT_PATTERNS,
        "approvers": DEFAULT_APPROVERS,
        "repos": []
    }

def get_since_date(time_range):
    """Calculate the --since date based on time range."""
    if not time_range:
        return None
    
    from datetime import datetime, timedelta
    
    now = datetime.now()
    if time_range == "last-24-hours":
        since_date = now - timedelta(hours=24)
    elif time_range == "last-7-days":
        since_date = now - timedelta(days=7)
    elif time_range == "last-14-days":
        since_date = now - timedelta(days=14)
    elif time_range == "last-30-days":
        since_date = now - timedelta(days=30)
    else:
        return None
    
    return since_date.strftime("%Y-%m-%d")

def save_config(config, config_file):
    """Save configuration to JSON file."""
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def make_github_request(url, headers, params=None):
    """
    Make a request to the GitHub API with rate limit handling.
    """
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and int(response.headers['X-RateLimit-Remaining']) == 0:
        reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
        wait_time = max(reset_time - time.time(), 0) + 1
        
        logging.warning(f"Rate limit exceeded. Waiting for {wait_time} seconds.")
        if wait_time > 300:
            raise RateLimitExceeded(f"GitHub API rate limit exceeded. Reset in {wait_time} seconds.")
        
        time.sleep(wait_time)
        return make_github_request(url, headers, params)
    
    response.raise_for_status()
    return response.json()

def clone_or_pull(repo_name, github_token=None):
    """Clone or pull the repository."""
    repo_dir = os.path.join(BASE_DIR, repo_name.split("/")[-1])
    
    # Create URLs - one for logging (without token) and one for operations (with token)
    safe_url = f"https://github.com/{repo_name}.git"
    auth_url = None
    
    if github_token:
        auth_url = f"https://{github_token}@github.com/{repo_name}.git"
    
    if not os.path.exists(repo_dir):
        logging.info(f"Cloning {repo_name}...")
        try:
            # Use auth URL for operations but don't log it
            Repo.clone_from(auth_url if github_token else safe_url, repo_dir)
        except Exception as e:
            error_msg = f"Error cloning repository {repo_name}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
            raise
    else:
        logging.info(f"Pulling latest from {repo_name}...")
        try:
            repo = Repo(repo_dir)
            origin = repo.remotes.origin
            
            # If token provided, temporarily update URL to include token
            original_url = None
            if github_token:
                original_url = list(origin.urls)[0]
                if "@github.com" not in original_url:
                    origin.set_url(auth_url)
            
            origin.pull()
            
            # Reset URL to non-token version
            if github_token and original_url and "@github.com" not in original_url:
                origin.set_url(original_url)
                
        except Exception as e:
            error_msg = f"Error pulling repository {repo_name}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
            raise
            
    return repo_dir

def get_direct_commits_to_main(repo_name, github_token):
    """
    Get commits made directly to main without going through a PR using Git.
    Uses 'git log --no-merges --first-parent origin/main' as requested.
    """
    direct_commits = []
    
    try:
        repo_dir = clone_or_pull(repo_name, github_token)
        repo = Repo(repo_dir)
        
        # Determine default branch
        default_branch = None

        try:

            repo.remotes.origin.fetch()

            for ref in repo.references:
                if ref.name == 'origin/main':
                    default_branch = 'origin/main'
                    break
                elif ref.name == 'origin/master':
                    default_branch = 'origin/master'
                    break
            
            if not default_branch:
                try:
                    head_ref = repo.remotes.origin.refs.HEAD.reference
                    default_branch = f"origin/{head_ref.name}"
                except:
                    pass

        except Exception as e:
            logging.warning(f"Could not fetch remote refs: {e}")
            
        if not default_branch:
            try:
                if 'main' in [b.name for b in repo.branches]:
                    default_branch = 'main'
                elif 'master' in [b.name for b in repo.branches]:
                    default_branch = 'master'
            except:
                pass

        if not default_branch:
            default_branch = 'main'
            
        logging.info(f"Default branch for {repo_name} is {default_branch}")
        
        # Find commits to main no PR
        try:
            direct_commit_cmd = ["git", "log", "--no-merges", "--first-parent", default_branch, "--format=%H||%an||%ad||%s"]
            since_date = get_since_date(getattr(analyze_repo, 'time_range', None))
            if since_date:
                direct_commit_cmd.extend(["--since", since_date])
            direct_commit_result = repo.git.execute(direct_commit_cmd, with_extended_output=True)[1]
            
            for line in direct_commit_result.strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split('||', 3)
                if len(parts) < 4:
                    continue
                    
                commit_hash, author, date, message = parts
                
                direct_commits.append({
                    "Repo": repo_name,
                    "Link": f'=HYPERLINK("https://github.com/{repo_name}/commit/{commit_hash}", "View Commit")',
                    "Hash": commit_hash,
                    "User": author,
                    "Date": f'"{date}"',  
                    "Message": message.replace('\n', ' | ').strip()
                })
                logging.info(f"Found direct commit: {commit_hash[:8]} - {message[:40]}...")
        
        except Exception as e:
            error_msg = f"Error processing commits for {repo_name}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
    
    except Exception as e:
        error_msg = f"Error getting direct commits for {repo_name}: {e}"
        logging.error(error_msg)
        error_logger.error(error_msg)
    
    return direct_commits

def get_pattern_matches(text, patterns):
    """Extract all keywords that match in a text based on patterns."""
    matches = {}
    
    for category, category_info in patterns.items():
        category_matches = []
        for pattern in category_info['patterns']:
            if re.search(r'\b' + re.escape(pattern) + r'\b', text, re.IGNORECASE):
                category_matches.append(pattern)
        
        if category_matches:
            matches[category] = category_matches
    
    return matches

def get_pr_approvers_and_changes(repo_name, github_token, patterns):
    """Get PR details including reviews and changes using both Git and GitHub API."""
    merge_approvers = []
    
    try:
        repo_dir = clone_or_pull(repo_name, github_token)
        repo = Repo(repo_dir)
        
        github_headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Get all merge commits
        merge_commits_cmd = ["git", "log", "--merges", "--format=%H||%an||%ad||%s"]
        since_date = get_since_date(getattr(analyze_repo, 'time_range', None))
        if since_date:
            merge_commits_cmd.extend(["--since", since_date])
        merge_commits_raw = repo.git.execute(merge_commits_cmd, with_extended_output=True)[1].strip().split('\n')
        
        for commit_line in merge_commits_raw:
            if not commit_line.strip():
                continue
                
            parts = commit_line.split('||', 3)
            if len(parts) < 4:
                continue
                
            commit_hash, author, date, message = parts
            
            # Extract PR number from commit message
            pr_number = None
            match = re.search(r'#(\d+)', message)
            if match:
                pr_number = match.group(1)
            else:
                match = re.search(r'[Mm]erge pull request (\d+)', message)
                if match:
                    pr_number = match.group(1)
            
            if not pr_number:
                continue
                
            # Get changes from diff
            pattern_matches = {}
            try:
                # Get the diff between the merge commit's first parent and the merge result
                diff_cmd = ["git", "diff", f"{commit_hash}^1", commit_hash]
                diff_output = repo.git.execute(diff_cmd, with_extended_output=True)[1]
                
                # Find pattern matches
                matches = get_pattern_matches(diff_output, patterns)
                for category, matched_patterns in matches.items():
                    pattern_matches[category] = matched_patterns
            except Exception as e:
                error_msg = f"Error getting diff for commit {commit_hash} in {repo_name}: {e}"
                logging.error(error_msg)
                error_logger.error(error_msg)
            
            # If no pattern matches, skip this PR
            if not pattern_matches:
                continue
                
            # Get PR reviewers from GitHub API
            approvers_by_team = {team: [] for team in patterns.keys()}
            try:
                reviews_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/reviews"
                reviews = make_github_request(reviews_url, github_headers)
                
                # Extract approved reviewers
                all_approvers = []
                for review in reviews:
                    if review.get('state') == 'APPROVED':
                        reviewer = review.get('user', {}).get('login')
                        if reviewer:
                            all_approvers.append(reviewer)
                
                # Map approvers to teams
                for approver in all_approvers:
                    for team, members in DEFAULT_APPROVERS.items():
                        if approver in members:
                            approvers_by_team[team].append(approver)
            except Exception as e:
                error_msg = f"Error getting reviews for PR #{pr_number} in {repo_name}: {e}"
                logging.error(error_msg)
                error_logger.error(error_msg)
            
            # RequiresAttention logic:
            # 1. No approvers at all on a merged PR
            # 2. IAM changes but no IAM approval
            # 3. Network changes but no Network approval
            # 4. NetSec changes but no NetSec approval
            requires_attention = False
            
            # Check if there are no approvers at all
            total_approvers = sum(len(approvers) for approvers in approvers_by_team.values())
            if total_approvers == 0:
                requires_attention = True
            
            # Check for specific team changes without matching approval
            for category, matched_patterns in pattern_matches.items():
                if matched_patterns and not approvers_by_team[category]:
                    requires_attention = True
                    break
            
            # Create merged categories string
            change_categories = []
            for category, matched_patterns in pattern_matches.items():
                if matched_patterns:
                    change_categories.append(category)
            
            change_category_str = "|".join(change_categories)
            
            # Create record
            record = {
                "Repo": repo_name,
                "Link": f'=HYPERLINK("https://github.com/{repo_name}/commit/{commit_hash}", "View Commit")',
                "Hash": commit_hash,
                "User": author,
                "Date": f'"{date}"', 
                "Message": message.replace('\n', ' | ').strip(),
                "ChangeCategory": change_category_str,
                "RequiresAttention": "Yes" if requires_attention else "No"
            }
            
            # Add team-specific fields
            for team in patterns.keys():
                # Add changes
                if team in pattern_matches and pattern_matches[team]:
                    record[f"{team}_changes"] = "|".join(pattern_matches[team])
                else:
                    record[f"{team}_changes"] = ""
                
                # Add approvers
                if approvers_by_team[team]:
                    record[f"{team}_approval"] = ", ".join(approvers_by_team[team])
                else:
                    record[f"{team}_approval"] = "No"
            
            merge_approvers.append(record)
            logging.info(f"Processed merge commit: {commit_hash[:8]} - PR #{pr_number}")
    
    except Exception as e:
        error_msg = f"Error processing PR data for {repo_name}: {e}"
        logging.error(error_msg)
        error_logger.error(error_msg)
    
    return merge_approvers

def write_csv(filename, data, mode="w"):
    """
    Write data to a CSV file with specific schema.
    The mode parameter allows for appending to existing files.
    """
    if not data:
        logging.warning(f"No data to write to {filename}")
        return
    
    write_header = mode == "w" or not os.path.exists(filename) or os.path.getsize(filename) == 0
    
    with open(filename, mode, newline="", encoding="utf-8") as f:
        if "direct_commits" in filename:
            # For direct commits, use specific column order
            fieldnames = ["Date", "Hash", "Link", "Repo", "User", "Message"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
            if write_header:
                writer.writeheader()
            for row in data:
                writer.writerow(row)
        else:
            # For merge approvers, get all fields and ensure correct order
            all_fields = set()
            for row in data:
                all_fields.update(row.keys())
            
            # Order fields appropriately
            ordered_fields = ["Date", "RequiresAttention", "Hash", "Link", "Repo", "User", "ChangeCategory", "Message"]
            
            # Add team-specific fields
            for field in sorted(list(all_fields)):
                if "_changes" in field or "_approval" in field:
                    ordered_fields.append(field)
            
            writer = csv.DictWriter(f, fieldnames=ordered_fields, quoting=csv.QUOTE_MINIMAL)
            if write_header:
                writer.writeheader()
            for row in data:
                writer.writerow(row)
    
    logging.info(f"Wrote {len(data)} rows to {filename}")

def analyze_repo(repo_name, patterns, github_token, time_range=None):
    """
    Analyze a repository and write results to files immediately.
    
    Parameters:
    - repo_name: Name of the repository to analyze
    - patterns: Patterns to look for in code
    - github_token: GitHub API token
    
    Global variables used:
    - check_direct: Whether to check for direct commits
    - check_approval: Whether to check for PR approvals
    - direct_commits_file: File to write direct commits to
    - merge_approvers_file: File to write merge approvals to
    """
    logging.info(f"Starting analysis of {repo_name}")
    analyze_repo.time_range = time_range
    
    try:
        # Get direct commits to main if requested
        if check_direct:
            direct_commits = get_direct_commits_to_main(repo_name, github_token)
            logging.info(f"Found {len(direct_commits)} direct commits in {repo_name}")
            
            # Write direct commits to file immediately
            if direct_commits_file and direct_commits:
                # Use append mode if the file already exists
                mode = "a" if os.path.exists(direct_commits_file) else "w"
                write_csv(direct_commits_file, direct_commits, mode)
        else:
            direct_commits = []
        
        # Get PRs with approvers and changes if requested
        if check_approval:
            merge_approvers = get_pr_approvers_and_changes(repo_name, github_token, patterns)
            logging.info(f"Found {len(merge_approvers)} PRs with relevant changes in {repo_name}")
            
            # Write merge approvers to file immediately
            if merge_approvers_file and merge_approvers:
                # Use append mode if the file already exists
                mode = "a" if os.path.exists(merge_approvers_file) else "w"
                write_csv(merge_approvers_file, merge_approvers, mode)
        else:
            merge_approvers = []
        
        return direct_commits, merge_approvers
    
    except Exception as e:
        error_msg = f"Error analyzing repository {repo_name}: {e}"
        logging.error(error_msg)
        error_logger.error(error_msg)
        return [], []

def init_config(config_file):
    """Initialize a new configuration file."""
    if os.path.exists(config_file):
        logging.info(f"Configuration file {config_file} already exists.")
        return
        
    config = {
        "patterns": DEFAULT_PATTERNS,
        "approvers": DEFAULT_APPROVERS,
        "repos": []
    }
    
    save_config(config, config_file)
    logging.info(f"Created new configuration file {config_file}")
    logging.info("Please edit this file to configure your patterns, approvers, and repositories.")

def main():
    """Main function to analyze repositories."""
    # Using an explicit variable scope for variables that need to be accessed in analyze_repo
    global check_direct, check_approval, direct_commits_file, merge_approvers_file
    
    parser = argparse.ArgumentParser(description="Git Repository Security Audit Tool")
    parser.add_argument("--config", default="git_audit_config.json", help="Path to configuration file")
    parser.add_argument("--init", action="store_true", help="Initialize a new configuration file")
    parser.add_argument("--repo", help="Single repository to analyze (owner/repo format)")
    parser.add_argument("--repos-file", help="File containing list of repositories (one per line)")
    parser.add_argument("--github-token", help="GitHub API token")
    parser.add_argument("--output-dir", default="reports", help="Directory for output files")
    parser.add_argument("--add-approver", nargs=2, metavar=('USERNAME', 'TEAM'), 
                       action='append', help="Add an approver to a team (can be used multiple times)")
    parser.add_argument("--add-criteria", nargs=2, metavar=('TEAM', 'PATTERN'),
                    action='append', help="Add a pattern to a team's criteria list")
    parser.add_argument("--direct-commits-only", action="store_true", 
                        help="Only check for direct commits to main branch")
    parser.add_argument("--approval-only", action="store_true", 
                        help="Only check for stakeholder approvals on PRs")
    parser.add_argument("--since", choices=["last-24-hours", "last-7-days", "last-14-days", "last-30-days"], help="Git log '--since' filter for commits")


    
    args = parser.parse_args()
    
    # Initialize configuration if requested
    if args.init:
        init_config(args.config)
        return
    
    # Load configuration
    config = load_config(args.config)
    patterns = config.get("patterns", DEFAULT_PATTERNS)
    
    # Add any approvers specified on the command line
    if args.add_approver:
        # Create config file if it doesn't exist
        if not os.path.exists(args.config):
            init_config(args.config)
     
        # Load config (or reload if we just created it)
        config = load_config(args.config)

        for username, team in args.add_approver:
            if team in config["approvers"]:
                if username not in config["approvers"][team]:
                    config["approvers"][team].append(username)
                    logging.info(f"Added approver {username} to team {team}")
            else:
                logging.warning(f"Team {team} not found in approvers map.")
        
        # Save changes to config file
        save_config(config, args.config)
        print(f"Updated approvers in {args.config}")

    # Add any criteria patterns specified on the command line
    if args.add_criteria:
        # Create config file if it doesn't exist
        if not os.path.exists(args.config):
            init_config(args.config)

        # Load config (or reload if we just created it)
        config = load_config(args.config)
            
        for team, pattern in args.add_criteria:
            if team in config["patterns"]:
                if pattern not in config["patterns"][team]["patterns"]:
                    config["patterns"][team]["patterns"].append(pattern)
                    logging.info(f"Added pattern '{pattern}' to {team}")
                else:
                    logging.info(f"Pattern '{pattern}' already exists in {team}")
            else:
                logging.warning(f"Team {team} not found in patterns map.")

        # Save changes to config file
        save_config(config, args.config)
        print(f"Updated criteria patterns in {args.config}")

    if args.add_approver and not args.repo and not args.repos_file and not config.get("repos"):
        print(f"Added approver(s) successfully.")
        return
        
    if args.add_criteria and not args.repo and not args.repos_file and not config.get("repos"):
        print(f"Added criteria pattern(s) successfully.")
        return

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(BASE_DIR, exist_ok=True)
    
    # Get list of repositories to analyze
    repos = []
    
    # Priority: command line repo > repos file > config file
    if args.repo:
        repos = [args.repo]
    elif args.repos_file:
        try:
            with open(args.repos_file) as f:
                repos = [line.strip() for line in f if line.strip()]
        except Exception as e:
            error_msg = f"Error reading repos file {args.repos_file}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
            return
    else:
        repos = config.get("repos", [])
    
    if not repos:
        logging.error("No repositories specified. Please add repositories to your config file, "
                     "use --repo option, or specify a file with --repos-file.")
        return
    
    # Get GitHub token
    github_token = args.github_token or os.getenv("GITHUB_TOKEN") or config.get("github_token")
    
    if not github_token:
        logging.error("GitHub token not provided. Please set GITHUB_TOKEN environment variable, "
                     "use --github-token option, or add it to your config file.")
        return
    
    # Determine which checks to run
    check_direct = not args.approval_only
    check_approval = not args.direct_commits_only
    
    # If both specific flags are set, warn the user
    if args.direct_commits_only and args.approval_only:
        logging.warning("Both --direct-commits-only and --approval-only are set. Running both checks.")
        check_direct = True
        check_approval = True
    
    # Create output file paths with timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    direct_commits_file = None
    merge_approvers_file = None
    
    if check_direct:
        direct_commits_file = os.path.join(args.output_dir, f"direct_commits-{timestamp}.csv")
    
    if check_approval:
        merge_approvers_file = os.path.join(args.output_dir, f"merge_approvers-{timestamp}.csv")
    
    # Analyze each repository and write results immediately
    for repo in repos:
        try:
            logging.info(f"\n====== Analyzing {repo} ======")
            direct_commits, merge_approvers = analyze_repo(
                repo_name=repo,
                patterns=patterns,
                github_token=github_token,
                time_range=args.since
            )
        except Exception as e:
            error_msg = f"Failed to analyze repository {repo}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
    
    # Final log message
    logging.info("\nAnalysis complete. CSV files created in the %s directory:", args.output_dir)
    if check_direct:
        logging.info("- %s: All direct commits to main without PR", direct_commits_file)
    if check_approval:
        logging.info("- %s: PRs with relevant changes and their approval status", merge_approvers_file)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        error_msg = f"Unexpected error in main execution: {e}"
        logging.error(error_msg)
        error_logger.error(error_msg)
