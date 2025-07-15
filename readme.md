Minion Log Analyzer
Minion is a Python-based log analyzer designed to help security analysts and system administrators detect suspicious activities within network and system logs. It currently supports:

C2 Beaconing Detection: Identifies potential command-and-control (C2) communication by analyzing HTTP requests and connection logs from Zeek (formerly Bro).

DNS Typo-squatting Analysis: Detects rare or typo-squatted DNS queries by comparing them against a baseline domain.

SSH Login Pattern Analysis with Geo-location: Analyzes SSH authentication logs, enriches them with geo-location data, and exports them to Elasticsearch for visualization in Kibana.

Table of Contents
Features

Prerequisites

Installation

Python Dependencies

GeoIP Database

Elasticsearch and Kibana (Docker Compose)

Usage

C2 Analysis

DNS Analysis

SSH Analysis with Geo-location

Log Formats

Contributing

License

Features
Beaconing Detection: Analyzes Zeek conn.log and http.log to find hosts making frequent, regular HTTP requests, indicative of C2 beaconing.

DNS Anomaly Detection: Identifies uncommon DNS queries and calculates their similarity to a specified legitimate domain, helping to spot typo-squatting or suspicious new domains.

SSH Log Enrichment: Parses auth.log entries, extracts relevant information, and enriches it with geographical data (country) based on the source IP address.

Elasticsearch Integration: Exports processed SSH logs to an Elasticsearch instance, enabling powerful searching and visualization.

Kibana Visualization: Designed to work seamlessly with Kibana for interactive dashboards and geographical mapping of SSH login attempts.

Prerequisites
Before you begin, ensure you have the following installed:

Python 3.x

Docker and Docker Compose (for Elasticsearch/Kibana setup)

Installation
Python Dependencies
Minion requires several Python libraries. You can install them using pip:

pip install -r requirements.txt

Create a requirements.txt file with the following content:

elasticsearch==7.17.0
python-geoip-lite==1.4.1

GeoIP Database
The SSH analysis feature relies on the python-geoip-lite library, which requires a GeoIP database. This database is usually downloaded automatically when the library is first used. However, if you encounter issues, you might need to ensure it's available.

Elasticsearch and Kibana (Docker Compose)
For SSH analysis and visualization, it's highly recommended to set up Elasticsearch and Kibana. This project provides a docker-compose.yml file to get a single-node instance running quickly.

Create docker-compose.yml:
Create a file named docker-compose.yml in your project root with the following content:

version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false # Disable security for simplicity in a local setup
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

Start the Stack:
Navigate to the directory containing docker-compose.yml and run:

docker-compose up -d

This will download the necessary Docker images and start Elasticsearch and Kibana in detached mode.

Verify Setup:

Elasticsearch should be accessible at http://localhost:9200.

Kibana should be accessible at http://localhost:5601.

Usage
The Minion analyzer is executed via the analyzer.py script (or Minion.py as it's named in the provided files).

General Help
To see the available modes and options:

python analyzer.py help

C2 Analysis
Detects beaconing activity from Zeek conn.log and http.log.

python analyzer.py c2-analysis <conn.log> <http.log> [output.log]

<conn.log>: Path to your Zeek connection log file.

<http.log>: Path to your Zeek HTTP log file.

[output.log]: (Optional) Path to export the beaconing data in JSON format.

Example:

python analyzer.py c2-analysis logs/conn.log logs/http.log output_beacons.json

DNS Analysis
Analyzes rare or typo-squatting DNS queries from Zeek dns.log.

python analyzer.py dns-analysis <dns.log> [output.log]

<dns.log>: Path to your Zeek DNS log file.

[output.log]: (Optional) Path to export the DNS anomaly data in JSON format.

Example:

python analyzer.py dns-analysis logs/dns.log output_dns_anomalies.json

SSH Analysis with Geo-location
Parses SSH auth.log files, enriches them with geo-location data, and exports them to Elasticsearch.

python analyzer.py ssh-analysis <auth.log>

<auth.log>: Path to your SSH authentication log file (e.g., /var/log/auth.log).

Example:

python analyzer.py ssh-analysis /var/log/auth.log

After running this command, the parsed and geo-enriched SSH logs will be indexed into Elasticsearch under the auth index.

Leveraging Geographic Info in Kibana
Once the SSH logs are in Elasticsearch, you can use Kibana to visualize the login attempts on a map.

Access Kibana: Open your web browser and go to http://localhost:5601.

Add Data View:

In Kibana, navigate to Stack Management -> Data Views.

Click Create data view.

For Index pattern name, enter auth* (or just auth if you only have this index).

For Timestamp field, select @timestamp (Elasticsearch automatically adds this when indexing).

Click Create data view.

Create a Map Visualization:

Go to Visualize -> Create new visualization.

Select Map.

Add a new layer. For the Layer type, choose Documents.

Select your auth data view.

Under Geo field, select the field that contains the geographic coordinates. If parse_Auth correctly stores geo data, it should be automatically mapped by Elasticsearch. The country field can be used for regional aggregation.

You can then customize the map, add filters, and explore the SSH login attempts visually. Kibana's Maps application is powerful for this purpose.

Log Formats
Minion expects log files to adhere to specific formats:

Zeek Logs (conn.log, http.log, dns.log): These files must be in the Zeek TSV format, including the #separator and #fields header lines.

SSH Logs (auth.log): The parse_Auth function is designed to parse standard Linux auth.log entries, typically found on Debian/Ubuntu or CentOS/RHEL systems.

Contributing
this buddy is not ready to roll yet, needs further tweaking, testing and more features to add to the usecase. but Contributions are welcome! Please feel free to fork the repository, make improvements, and submit pull requests.

Y.