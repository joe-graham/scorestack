#!/bin/bash

ELASTICSEARCH_HOST=elasticsearch:9200
KIBANA_HOST=kibana:5601
CHECK_FOLDER=checks/tor
USERNAME=root
PASSWORD='u#96@o8!5q%Amwgrmqi$NYWb'

# Wait for elasticsearch to come up
while [[ "$(curl -sku ${USERNAME}:${PASSWORD} "https://${ELASTICSEARCH_HOST}/_cluster/health" | jq -r .status 2>/dev/null)" != "green" ]]
do
  echo "Waiting for Elasticsearch to be ready..."
  sleep 5
done

# Wait for kibana to come up
while [[ "$(curl -sku ${USERNAME}:${PASSWORD} https://${KIBANA_HOST}/api/status | jq -r .status.overall.state 2>/dev/null)" != "green" ]]
do
  echo "Waiting for Kibana to be ready..."
  sleep 5
done

for check in $(find ${CHECK_FOLDER} -maxdepth 1 -mindepth 1 -type d -printf "%f\n")
do
  # Add check definition
  cat ${CHECK_FOLDER}/${check}/check.json > check.tmp.json
  ID=$(cat check.tmp.json | jq -r '.id')
  curl -k -XPUT -u ${USERNAME}:${PASSWORD} https://${ELASTICSEARCH_HOST}/checkdef/_doc/${ID} -H 'Content-Type: application/json' -d @check.tmp.json
  cat check.tmp.json | jq '{id, name, type, group}' > generic-check.tmp.json
  curl -k -XPUT -u ${USERNAME}:${PASSWORD} https://${ELASTICSEARCH_HOST}/checks/_doc/${ID} -H 'Content-Type: application/json' -d @generic-check.tmp.json

  # Add admin attributes, if they are defined
  if [ -f ${CHECK_FOLDER}/${check}/admin-attribs.json ]
  then
    cat ${CHECK_FOLDER}/${check}/admin-attribs.json > ${CHECK_FOLDER}/${check}/admin-attribs.tmp.json
    curl -k -XPUT -u ${USERNAME}:${PASSWORD} https://${ELASTICSEARCH_HOST}/attrib_admin_${TEAM}/_doc/${ID} -H "Content-Type: application/json" -d @${CHECK_FOLDER}/${check}/admin-attribs.tmp.json
    rm -f ${CHECK_FOLDER}/${check}/admin-attribs.tmp.json
  fi

  # Add user attributes, if they are defined
  if [ -f ${CHECK_FOLDER}/${check}/user-attribs.json ]
  then
    cat ${CHECK_FOLDER}/${check}/user-attribs.json > ${CHECK_FOLDER}/${check}/user-attribs.tmp.json
    curl -k -XPUT -u ${USERNAME}:${PASSWORD} https://${ELASTICSEARCH_HOST}/attrib_user_${TEAM}/_doc/${ID} -H "Content-Type: application/json" -d @${CHECK_FOLDER}/${check}/user-attribs.tmp.json
    rm -f ${CHECK_FOLDER}/${check}/user-attribs.tmp.json
  fi
done

# Clean up
rm -f check.tmp.json
rm -f generic-check.tmp.json
rm -f admin-attribs.tmp.json
rm -f user-attribs.tmp.json
