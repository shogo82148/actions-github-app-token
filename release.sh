#!/bin/bash

set -uex

CURRENT=$(cd "$(dirname "$0")" && pwd)

# if version starts with 'v', remove it
VERSION=${1#v}

MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
PATCH=$(echo "$VERSION" | cut -d. -f3)
WORKING=$CURRENT/.working

: clone
ORIGIN=$(git remote get-url origin)
rm -rf "$WORKING"
git clone "$ORIGIN" "$WORKING"
cd "$WORKING"

: checkout releases branch
git checkout -b "releases/v$MAJOR" "origin/releases/v$MAJOR" || git checkout -b "releases/v$MAJOR" main
git merge -X theirs -m "Merge branch 'main' into releases/v$MAJOR" main || true

: update the version of package.json
cd "$WORKING/action"
jq ".version=\"$MAJOR.$MINOR.$PATCH\"" < package.json > .tmp.json
mv .tmp.json package.json
jq ".version=\"$MAJOR.$MINOR.$PATCH\"" < package-lock.json > .tmp.json
mv .tmp.json package-lock.json

: build the action
npm ci
npm run build

: remove development packages from node_modules
npm prune --production
perl -ne 'print unless m(^/node_modules/|/lib/$)' -i .gitignore

: publish to GitHub
git add .
git commit -m "bump up to v$MAJOR.$MINOR.$PATCH" || true
git push origin "releases/v$MAJOR"
git tag -a "v$MAJOR.$MINOR.$PATCH" -m "release v$MAJOR.$MINOR.$PATCH"
git push origin "v$MAJOR.$MINOR.$PATCH"

git tag -fa "v$MAJOR" -m "release v$MAJOR.$MINOR.$PATCH"
git push -f origin "v$MAJOR"

cd "$CURRENT"
rm -rf "$WORKING"
