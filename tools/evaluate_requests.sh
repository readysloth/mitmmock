#!/usr/bin/env bash

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
