#!/usr/bin/env bash

set -e

MESSAGE="$*"

if [ -z "$MESSAGE" ]; then
    echo "Usage: ./script.sh \"your commit message\""
    exit 1
fi

echo "📦 Adding changes..."
git add .

echo "📝 Committing: $MESSAGE"
git commit -m "$MESSAGE"

echo "🚀 Pushing..."
git push

echo "✅ Done!"