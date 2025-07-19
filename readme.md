# Minion Log Analyzer

```

 ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
 ████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
 ██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
 ██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
 ██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
 ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝  

```

## Overview


**Minion** is a Python-based log analyzer designed to help security analysts and system administrators detect suspicious activities within network and system logs.

---

## Table of Contents

* [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)

  * [Python Dependencies](#python-dependencies)
  * [GeoIP Database](#geoip-database)
  * [Elasticsearch and Kibana (Docker Compose)](#elasticsearch-and-kibana-docker-compose)
* [Usage](#usage)

  * [General Help](#general-help)
  * [C2 Analysis](#c2-analysis)
  * [DNS Analysis](#dns-analysis)
  * [SSH Analysis with Geo-location](#ssh-analysis-with-geo-location)
  * [Leveraging Geographic Info in Kibana](#leveraging-geographic-info-in-kibana)
* [Log Formats](#log-formats)
* [Contributing](#contributing)


---

## Features

* **Beaconing Detection**: Analyzes Zeek `conn.log` and `http.log` to find hosts making frequent, regular HTTP requests, indicative of C2 beaconing.
* **DNS Anomaly Detection**: Identifies uncommon DNS queries and calculates their similarity to a specified legitimate domain, helping to spot typo-squatting or suspicious new domains.
* **SSH Log Enrichment**: Parses `auth.log` entries, extracts relevant information, and enriches it with geographical data (country) based on the source IP address.
* **Elasticsearch Integration**: Exports processed SSH logs to an Elasticsearch instance, enabling powerful searching and visualization.
* **Kibana Visualization**: Designed to work seamlessly with Kibana for interactive dashboards and geographical mapping of SSH login attempts.

---

## Prerequisites

Make sure the following are installed on your system:

* Python 3.x
* Docker and Docker Compose

---

## Installation

### Python Dependencies

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

**`requirements.txt`**:

```text
elasticsearch==7.17.0
python-geoip-lite==1.4.1
```

### GeoIP Database

The `python-geoip-lite` library downloads the GeoIP database automatically on first use. If it fails, ensure the database is available manually.

### Elasticsearch and Kibana (Docker Compose)

Create a `docker-compose.yml` file in your project root:

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
      - "9300:9300"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1
    networks:
      - elastic-network

  kibana:
    image: docker.elastic.co/kibana/kibana:7.17.0
    container_name: kibana
    ports:
      - "5601:5601"
    environment:
      ELASTICSEARCH_HOSTS: 'http://elasticsearch:9200'
    depends_on:
      - elasticsearch
    networks:
      - elastic-network

volumes:
  esdata:
    driver: local

networks:
  elastic-network:
    driver: bridge
```

Start the services:

```bash
docker-compose up -d
```

Verify:

* Elasticsearch: [http://localhost:9200](http://localhost:9200)
* Kibana: [http://localhost:5601](http://localhost:5601)

---

## Usage

Run via `analyzer.py` (or `Minion.py` if that's the provided name).

### General Help

```bash
python analyzer.py help
```

### C2 Analysis

```bash
python analyzer.py c2-analysis <conn.log> <http.log> [output.log]
```

**Example:**

```bash
python analyzer.py c2-analysis logs/conn.log logs/http.log output_beacons.json
```

### DNS Analysis

```bash
python analyzer.py dns-analysis <dns.log> [output.log]
```

**Example:**

```bash
python analyzer.py dns-analysis logs/dns.log output_dns_anomalies.json
```

### SSH Analysis with Geo-location

```bash
python analyzer.py ssh-analysis <auth.log>
```

**Example:**

```bash
python analyzer.py ssh-analysis /var/log/auth.log
```

---

## Leveraging Geographic Info in Kibana

1. Open Kibana at [http://localhost:5601](http://localhost:5601).
2. Navigate to **Stack Management > Data Views**.
3. Click **Create data view**.
4. Set Index pattern name to `auth*` or `auth`.
5. Set Timestamp field to `@timestamp`.
6. Create and go to **Visualize > Create new visualization > Map**.
7. Add new **Documents** layer, select your `auth` view, and choose geo field.
8. Customize and analyze.

---

## Log Formats

* **Zeek Logs**: TSV format with `#separator` and `#fields` headers.
* **SSH Logs**: Standard Linux `auth.log` format (Debian/Ubuntu, CentOS/RHEL).

---

## Contributing

this buddy is still not completely ready to roll, so contributions are welcome!

Y.
---
