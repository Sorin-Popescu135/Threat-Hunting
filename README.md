# Single-Node Threat Hunting Lab with ELK, ElastAlert2, and Sigma rules

This project provides a complete, end-to-end Windows security monitoring solution. It is designed to help you collect, visualize, and alert on security-relevant events from Windows hosts in real time.

---

## Overview

**What does it do?**

- **Collects detailed security and system events** from Windows machines using [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
- **Ships those logs** to a centralized ELK (Elasticsearch, Logstash, Kibana) stack using [Winlogbeat](https://www.elastic.co/beats/winlogbeat).
- **Indexes and analyzes logs** in [Elasticsearch](https://www.elastic.co/elasticsearch).
- **Visualizes events and trends** in [Kibana](https://www.elastic.co/kibana).
- **Detects threats and anomalies** using [Sigma rules](https://github.com/SigmaHQ/sigma).
- **Sends real-time alerts** on suspicious activity via [ElastAlert2](https://elastalert2.readthedocs.io/).

---

## Technologies Used

- **Sysmon:**  
  Windows system service that logs detailed OS activity such as process creation, network connections, and file changes.  
  _Runs on monitored Windows endpoints._

- **Winlogbeat:**  
  Lightweight agent that ships Windows Event Logs (including Sysmon logs) to Elasticsearch.  
  _Runs on monitored Windows endpoints._

- **ELK Stack:**  
  - **Elasticsearch:** Search and analytics engine for storing and querying logs.
  - **Kibana:** Web UI for visualizing and exploring log data.
  - **Logstash (optional):** For advanced log processing and enrichment.

- **ElastAlert2:**  
  Flexible alerting framework that monitors Elasticsearch for defined conditions and sends alerts (email, Slack, etc.) as needed.

- **Sigma:**  
  Open and generic signature format for SIEM systems, used to describe detection rules in a standardized way.

---

## How It Works

1. **Sysmon** monitors Windows activity and writes detailed event logs.
2. **Winlogbeat** reads Sysmon (and other Windows Event) logs and forwards them to the ELK stack.
3. **Elasticsearch** stores and indexes all received logs for fast search and analysis.
4. **Kibana** provides dashboards and visualizations for interactive exploration of incoming data.
5. **Sigma rules** are converted and deployed to automate detection.
6. **ElastAlert2** runs rules on the indexed data, triggering alerts when suspicious patterns are detected.

---

## Sigma Rules

[Sigma](https://github.com/SigmaHQ/sigma) is an open standard for writing generic detection rules for security events. In this project, Sigma rules can be used to:

- Detect threats and anomalies in your log data.
- Standardize detection logic across different environments.
- Quickly adapt to new threats by updating or adding new rules.

### How to use Sigma rules in this project

1. **Download Sigma rules** relevant to your environment.
2. **Convert Sigma rules** to ElastAlert2 format using the [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

   ```sh
   sigma convert --target elastalert --without-pipeline <path-to-sigma-rules> -o <output-rule-file-or-directory>
   ```

   - Replace `<path-to-sigma-rules>` with the directory or file containing your Sigma rules.
   - Replace `<output-rule-file-or-directory>` with the ElastAlert2 rules folder or desired output file.

3. **Separate each ElastAlert rule into its own file** inside the ElastAlert2 rules directory.

4. **Enable email alerts:**  
   At the end of each ElastAlert2 rule file, add the following lines to configure email alerts:

   ```yaml
   alert:
     - email
   email: <email_that_receives_the_alert>
   ```
   Replace `<email_that_receives_the_alert>` with your own email address.

---

## Setup Guide

> **Note:**  
> This project is designed for a single-node setup—all components (Elasticsearch, Kibana, Logstash, ElastAlert2) run on the same host via Docker Compose.

### 1. Prerequisites

- [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/) installed on the host that will run the ELK stack containers.
- This repository (clone or download).

### 2. Install on Each Windows Host (including the host running the ELK stack, if it's a Windows machine)

#### **a. Sysmon**
- Download Sysmon from the official [Sysinternals page](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
- Install Sysmon as a service:
  ```sh
  sysmon.exe -accepteula -i <path-to-config.xml>
  ```
  - `<path-to-config.xml>` is your Sysmon configuration file. You can find community configs [here](https://github.com/SwiftOnSecurity/sysmon-config).

#### **b. Winlogbeat**
- Download Winlogbeat from the [Elastic downloads page](https://www.elastic.co/downloads/beats/winlogbeat).
- Unzip and install as a service:
  ```sh
  winlogbeat.exe install
  ```
- Configure `winlogbeat.yml`:
  - Set up the output to point to your Elasticsearch instance (use `localhost` or `127.0.0.1` if Winlogbeat runs on the same host as the ELK stack, otherwise use the host's IP).
  - Enable modules and event logs relevant to Sysmon and Windows event logs.
- Start the service:
  ```sh
  Start-Service winlogbeat
  ```

### 3. Start the ELK Stack (Single Node)

- Set up `.env` with your desired configuration and secrets.
- Launch the containers:
  ```sh
  docker compose up -d
  ```

### 4. Configure Elasticsearch & Kibana

- **Elasticsearch:**  
  The stack will be accessible at [http://localhost:9200](http://localhost:9200) by default (or the host/port you set in `.env`).
- **Kibana:**  
  Access the dashboard at [http://localhost:5601](http://localhost:5601).  
  Log in with the `elastic` user and password you set in your `.env` file.
- **Index Patterns:**  
  Configure index patterns in Kibana to match your Winlogbeat indices (e.g., `winlogbeat-*`).

---

## References

- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Winlogbeat](https://www.elastic.co/beats/winlogbeat)
- [Elasticsearch](https://www.elastic.co/elasticsearch)
- [Kibana](https://www.elastic.co/kibana)
- [ElastAlert2](https://elastalert2.readthedocs.io/)
- [Sigma](https://github.com/SigmaHQ/sigma)
- [Sysmon Community Config](https://github.com/SwiftOnSecurity/sysmon-config)