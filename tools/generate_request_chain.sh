#!/usr/bin/env bash

set -e

poetry run mitmdump --server --save-stream-file request_chain.mdump &
MITMDUMP_PID="$!"

close_mitmdump() {
      kill "$MITMDUMP_PID"
}

trap close_mitmdump ERR EXIT

until ss --tcp --listening --no-header 'sport = 8080' | grep . &>/dev/null
do
      :
done

export HTTP_PROXY=127.0.0.1:8080
export HTTPS_PROXY=127.0.0.1:8080
export FTP_PROXY=127.0.0.1:8080

cat << EOF | poetry run python
import requests

response = requests.post('https://dummyjson.com/auth/login',
                         verify=False,
                         json={'username': 'kminchelle',
                               'password': '0lelplR'})
user_credentials = response.json()
user_token = user_credentials['token']

for i in range(5):
      response = requests.get(f'https://dummyjson.com/products/{i}',
                              verify=False,
                              headers={'Bearer': user_token})
EOF

kill "$MITMDUMP_PID"
