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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("git_audit.log"),
        logging.StreamHandler()
    ]
)
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_file_handler = logging.FileHandler("errors.txt")
error_file_handler.setLevel(logging.ERROR)
error_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_file_handler)

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
    
    clone_url = f"https://github.com/{repo_name}.git"
    if github_token:
        clone_url = f"https://{github_token}@github.com/{repo_name}.git"
        
    if not os.path.exists(repo_dir):
        logging.info(f"Cloning {repo_name}...")
        try:
            Repo.clone_from(clone_url, repo_dir)
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
            origin.pull()
        except Exception as e:
            error_msg = f"Error pulling repository {repo_name}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
            raise
            
    return repo_dir

def get_direct_commits_to_main(repo_name, github_token):
    """Get commits made directly to main without going through a PR using Git."""
    direct_commits = []
    
    try:
        repo_dir = clone_or_pull(repo_name, github_token)
        repo = Repo(repo_dir)
        
        # Determine default branch
        default_branch = None
        for ref in repo.references:
            if ref.name == 'origin/main':
                default_branch = 'main'
                break
            elif ref.name == 'origin/master':
                default_branch = 'master'
                break
        
        if not default_branch:
            # Try to get from remote info
            for remote in repo.remotes:
                for ref in remote.refs:
                    if ref.name in ['origin/HEAD', 'origin/main', 'origin/master']:
                        if 'main' in ref.name:
                            default_branch = 'main'
                        else:
                            default_branch = 'master'
                        break
        
        if not default_branch:
            default_branch = 'main'
            
        logging.info(f"Default branch for {repo_name} is {default_branch}")
        
        # Step 1: Get all non-merge commits on main
        try:
            non_merge_cmd = ["git", "log", "--no-merges", default_branch, "--format=%H %an %ad %s"]
            non_merge_result = repo.git.execute(non_merge_cmd, with_extended_output=True)[1]
            all_non_merge_commits = non_merge_result.strip().split('\n')
            
            # Step 2: Get second parents of all merge commits (branch commits that were merged)
            merge_parents_cmd = ["git", "log", "--merges", "--format=%P"]
            merge_parents_result = repo.git.execute(merge_parents_cmd, with_extended_output=True)[1]
            
            # Extract second parents (branch being merged)
            branch_parents = []
            for line in merge_parents_result.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) > 1:
                    branch_parents.append(parts[1])  # Second parent
            
            # Step 3: Get all commits that were originally from branches
            branch_commits = set()
            for parent in branch_parents:
                if parent.strip():  # Skip empty lines
                    branch_cmd = ["git", "log", "--format=%H", parent]
                    branch_result = repo.git.execute(branch_cmd, with_extended_output=True)[1]
                    for commit in branch_result.strip().split('\n'):
                        if commit.strip():
                            branch_commits.add(commit.strip())
            
            # Filter for direct commits (not from branches, not merges)
            for line in all_non_merge_commits:
                if not line.strip():
                    continue
                    
                # Extract commit hash and check if it's a direct commit
                parts = line.split(' ', 1)
                if not parts:
                    continue
                    
                commit_hash = parts[0]
                if commit_hash not in branch_commits:
                    # Get full commit details
                    commit_cmd = ["git", "log", "-1", "--format=%an||%ad||%s", commit_hash]
                    commit_details = repo.git.execute(commit_cmd, with_extended_output=True)[1].strip()
                    
                    if commit_details:
                        author, date, message = commit_details.split('||', 2)
                        
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
            
            # Determine if this PR requires attention
            requires_attention = False
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
                "Date": f'"{date}"',  # Properly quoted date
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

def write_csv(filename, data):
    """Write data to a CSV file with specific schema."""
    if not data:
        logging.warning(f"No data to write to {filename}")
        return
    
    with open(filename, "w", newline="", encoding="utf-8") as f:
        if "direct_commits" in filename:
            # For direct commits, use specific column order
            fieldnames = ["Date", "Hash", "Link", "Repo", "User", "Message"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
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
            writer.writeheader()
            for row in data:
                writer.writerow(row)
    
    logging.info(f"Wrote {len(data)} rows to {filename}")

def analyze_repo(repo_name, patterns, github_token):
    """Analyze a repository."""
    logging.info(f"Starting analysis of {repo_name}")
    
    try:
        # Get direct commits to main
        direct_commits = get_direct_commits_to_main(repo_name, github_token)
        logging.info(f"Found {len(direct_commits)} direct commits in {repo_name}")
        
        # Get PRs with approvers and changes
        merge_approvers = get_pr_approvers_and_changes(repo_name, github_token, patterns)
        logging.info(f"Found {len(merge_approvers)} PRs with relevant changes in {repo_name}")
        
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
    
    # Lists to store results from all repos
    all_direct_commits = []
    all_merge_approvers = []
    
    # Analyze each repository
    for repo in repos:
        try:
            logging.info(f"\n====== Analyzing {repo} ======")
            direct_commits, merge_approvers = analyze_repo(repo, patterns, github_token)
            
            all_direct_commits.extend(direct_commits)
            all_merge_approvers.extend(merge_approvers)
        except Exception as e:
            error_msg = f"Failed to analyze repository {repo}: {e}"
            logging.error(error_msg)
            error_logger.error(error_msg)
    
    # Write results to CSV files
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    
    direct_commits_file = os.path.join(args.output_dir, f"direct_commits-{timestamp}.csv")
    merge_approvers_file = os.path.join(args.output_dir, f"merge_approvers-{timestamp}.csv")
    
    write_csv(direct_commits_file, all_direct_commits)
    write_csv(merge_approvers_file, all_merge_approvers)
    
    logging.info("\nAnalysis complete. CSV files created in the %s directory:", args.output_dir)
    logging.info("- %s: All direct commits to main without PR", direct_commits_file)
    logging.info("- %s: PRs with relevant changes and their approval status", merge_approvers_file)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        error_msg = f"Unexpected error in main execution: {e}"
        logging.error(error_msg)
        error_logger.error(error_msg)