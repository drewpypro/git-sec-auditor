# git-sec-auditor
[![codecov](https://codecov.io/gh/drewpypro/git-sec-auditor/graph/badge.svg?token=L7TBV3T029)](https://codecov.io/gh/drewpypro/git-sec-auditor)
![auditor-agent](img/auditor.gif)

Audit tool that scans git repos for direct commits to main and changes requiring specific team approvals.

## What it does

- Detects direct pushes to main branch (bad practice)
- Finds PRs with security/IAM/network changes that lack required team approvals
- Produces two CSV reports:
  - `direct_commits-TIMESTAMP.csv` - Lists all direct commits to main
  - `merge_approvers-TIMESTAMP.csv` - Lists PRs needing approval from specific teams

## Install & run

```bash
# Install deps
pip install gitpython requests

# Setup config (edit after creation)
python git-sec-auditor.py --init

# Run audit
python git-sec-auditor.py --repos-file my-repos.txt --github-token YOUR_TOKEN

# Add approvers on the fly
python git-sec-auditor.py --add-approver alice network_security --add-approver bob iam

# Add criteria on the fly
python git-sec-auditor.py --add-criteria iam principal

# Use since functionality
python git-sec-auditor.py --since last-14-days 

```

## Config

Edit `git-sec-auditor_config.json` to customize:
- Patterns to match for each team (security, IAM, network)
- Team approvers list
- Default repo list

## Usage

```
usage: git-sec-auditor.py [-h] [--config CONFIG] [--init] [--repo REPO]
                    [--repos-file REPOS_FILE] [--github-token GITHUB_TOKEN]
                    [--output-dir OUTPUT_DIR]
                    [--add-approver USERNAME TEAM]
```

Fix your approval workflows