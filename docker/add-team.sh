#!/bin/bash

TEAM="${1}"

# Add example checks for the team
for check in $(find examples -maxdepth 1 -mindepth 1 -type d -printf "%f\n")
do
  # Add check definition
  cat examples/${check}/check.json | jq --arg TEAM "$TEAM" '.group = $TEAM | .id = "\(.id)-\($TEAM)"' > check.tmp.json
  ID=$(cat check.tmp.json | jq -r '.id')
  curl -k -XPUT -u root:changeme https://localhost:9200/checks/_doc/${ID} -H 'Content-Type: application/json' -d @check.tmp.json

  # Add admin attributes, if they are defined
  if [ -f examples/${check}/admin-attribs.json ]
  then
    curl -k -XPUT -u root:changeme https://localhost:9200/attrib_admin_${ID}/_doc/attributes -H "Content-Type: application/json" -d @examples/${check}/admin-attribs.json
  fi

  # Add user attributes, if they are defined
  if [ -f examples/${check}/user-attribs.json ]
  then
    curl -k -XPUT -u root:changeme https://localhost:9200/attrib_user_${ID}/_doc/attributes -H "Content-Type: application/json" -d @examples/${check}/user-attribs.json
  fi
done

# Add team role

# Add team user