#!/bin/bash

ROOT_USERNAME=root
ROOT_PASSWORD=changeme
ELASTICSEARCH_HOST=localhost:9200

if [ $# -ne 1 ]; then
    echo "Usage: $0 creds_filename"
    exit
fi

# Wait for elasticsearch to come up
while [[ "$(curl -sku ${ROOT_USERNAME}:${ROOT_PASSWORD} "https://${ELASTICSEARCH_HOST}/_cluster/health" | jq -r .status 2>/dev/null)" != "green" ]]
do
  echo "Waiting for Elasticsearch to be ready..."
  sleep 5
done

while read line; do
    username=$(echo -n $line | cut -d':' -f1)
    password=$(echo -n $line | cut -d':' -f2)
    curl -kX POST -u ${ROOT_USERNAME}:${ROOT_PASSWORD} -H "Content-Type: application/json" https://${ELASTICSEARCH_HOST}/_security/user/${username}/_password -d '{"password":"'${password}'"}'
done < $1