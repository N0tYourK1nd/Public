#!/bin/bash
exclusionDirectories=(
    ".local"
    ".share"
    ".cache"
)

# Combine exclusions into a single grep pattern
exclusionCombined=$(IFS='|'; echo "${exclusionDirectories[*]/#//}" | sed 's/\./\\./g')

# Find git repos excluding the directories
gitRepos=($(find "$HOME" -type d -name '.git' 2>/dev/null | grep -vE "($exclusionCombined)"))

# Iterate over each repo 
for repo in "${gitRepos[@]}"; do
    repoDir=$(dirname "$repo")
    echo "Updating repository in $repoDir"
    cd "$repoDir" || continue
    git pull --ff-only
done
