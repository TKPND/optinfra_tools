# ELK-Mail IMAP Ingestion

This directory contains a simple proof of concept for ingesting alert mails via IMAP into an Elastic stack running on a single host using Docker Compose.

## Directory Layout

- `docker-compose.yml` – Docker Compose file bringing up Elasticsearch, Kibana and a custom Logstash image.
- `extensions/logstash/Dockerfile` – builds Logstash with the `logstash-input-imap` plugin.
- `logstash/pipeline/mail_imap.conf` – Logstash pipeline definition for pulling mails from IMAPS and indexing them into Elasticsearch.

## Usage

1. Build the custom Logstash image:
   ```bash
   docker compose build
   ```
2. Start the stack:
   ```bash
   docker compose up -d
   ```
3. Create the ILM policy and index template:
   ```bash
   bash setup_ilm.sh
   ```
4. Access Kibana at `http://localhost:5601` and add the index pattern `imap-mail-*`.

A basic setup script `setup_ilm.sh` is provided to configure the rollover and retention policy described in the specification.
