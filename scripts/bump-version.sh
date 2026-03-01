#!/usr/bin/env bash
#
# bump-version.sh — Update version across all packages
#
# Usage:
#   ./scripts/bump-version.sh 0.5.1
#
# Updates pyproject.toml and __init__.py version strings in the
# sift-mcp monorepo and the aiir repo (if present at ../aiir).
#
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.5.1"
    exit 1
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AIIR_DIR="$REPO_ROOT/../aiir"

# Validate version format
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in X.Y.Z format (got: $VERSION)"
    exit 1
fi

echo "Bumping to $VERSION"
echo ""

count=0

# Update all pyproject.toml in sift-mcp
while IFS= read -r file; do
    if grep -q '^version = "' "$file"; then
        sed -i "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" "$file"
        echo "  Updated: ${file#$REPO_ROOT/}"
        count=$((count + 1))
    fi
done < <(find "$REPO_ROOT" -name pyproject.toml -not -path "*/.*")

# Update __version__ in __init__.py files in sift-mcp
while IFS= read -r file; do
    if grep -q '^__version__ = "' "$file"; then
        sed -i "s/^__version__ = \"[^\"]*\"/__version__ = \"${VERSION}\"/" "$file"
        echo "  Updated: ${file#$REPO_ROOT/}"
        count=$((count + 1))
    fi
done < <(find "$REPO_ROOT" -name "__init__.py" -not -path "*/.*")

# Update aiir if present
if [[ -f "$AIIR_DIR/pyproject.toml" ]]; then
    sed -i "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" "$AIIR_DIR/pyproject.toml"
    echo "  Updated: ../aiir/pyproject.toml"
    count=$((count + 1))
fi

echo ""
echo "$count files updated to $VERSION"
echo ""
echo "Next steps:"
echo "  1. Review:  git diff"
echo "  2. Commit:  git commit -am 'bump version to $VERSION'"
echo "  3. Tag:     git tag v$VERSION"
echo "  4. Push:    git push && git push --tags"
echo "  5. Release: gh release create v$VERSION --title 'v$VERSION' --generate-notes"
