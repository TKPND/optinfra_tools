#!/bin/bash
set -e

curl -X PUT localhost:9200/_ilm/policy/imap_policy -H 'Content-Type: application/json' -d '{
  "policy": {
    "phases": {
      "hot": {"actions": {"rollover": {"max_age": "30d", "max_size": "5gb"}}},
      "delete": {"min_age": "180d", "actions": {"delete": {}}}
    }
  }
}'

curl -X PUT localhost:9200/_index_template/imap_mail_template -H 'Content-Type: application/json' -d '{
  "index_patterns": ["imap-mail-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "imap_policy",
      "index.lifecycle.rollover_alias": "imap-mail"
    }
  }
}'
