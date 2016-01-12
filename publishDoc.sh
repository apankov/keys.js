#!/usr/bin/env sh

# Publish documentation to the Eris website.

base_name=basename $PWD
user_name=eris-ltd
docs_site=docs.erisindustries.com
repo=`pwd`
release_min=$(cat package.json | jq --raw-output .version)

# -------------------------------------------------------------------
# Build

npm run doc

cd $HOME
git clone git@github.com:$user_name/$docs_site.git
cd $docs_site/documentation
mkdir --parents $base_name
cd $base_name
mv $repo/doc $release_min
ln --symbolic $release_min latest

# ------------------------------------------------------------------
# Commit and push if there are changes.

if [ -z "$(git status --porcelain)" ]; then
  echo "All Good!"
else
  git config --global user.email "billings@erisindustries.com"
  git config --global user.name "Billings the Bot"
  git add -A :/ &&
  git commit -m "$base_name build number $CIRCLE_BUILD_NUM doc generation" &&
  git push origin master
fi
