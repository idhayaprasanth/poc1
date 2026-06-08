# AI Security Monitoring Project

A unified cybersecurity monitoring dashboard built with Python and Dash. This project aggregates multiple security data sources (vulnerabilities, threats, logs, and patch status) into a centralized asset inventory. Risk scoring and remediation recommendations are generated through a DGX Spark Server endpoint, and the results are presented through an analyst-friendly interface with actionable insights.

## Features

* Unified asset inventory from multiple data sources
* AI-driven risk scoring (powered by DGX Spark Server)
* AI-generated remediation recommendations
* KPI overview for quick situational awareness
* Interactive data table with filtering
* Asset detail panel for deeper analysis
* SLA aging analysis
* AI-generated security insights
* Integrated AI chat assistant

## Data Processing and AI Analysis Flow

The application processes security events and coordinates with the AI analysis engine through the following automated pipeline:

### 1. Ingestion of Security Data Sources
Data is ingested from three primary CSV data sources located in `security_dashboard/data/seed_data/`:
* **Tenable**: Vulnerability data containing Plugin IDs, severity impact, CVE mappings, and vendor-recommended solutions.
* **Defender**: Endpoint detection alerts indicating process name, file path, threat impact, and status.
* **Splunk**: Security event logs detailing anomaly events, rule triggers, source anomaly scores, and recommendations.

### 2. Merging & Normalization
* The datasets are read, normalized, and mapped based on their configured column aliases in `security_dashboard/data/datasets.py`.
* A join is performed on `asset_name` (representing the Hostname) to aggregate Tenable, Defender, and Splunk alerts under unified records.
* The system keeps the Hostname (`host-001`) and the unique `Asset ID` (`asset-001`) distinct.

### 3. Payload Creation
For each merged asset, the system builds a structured JSON payload representing all collected security metrics:
```json
{
  "asset_id": "asset-001",
  "sources": {
    "tenable": [
      {
        "Severity": "Critical",
        "Name": "OpenSSH RCE Exposure",
        "State": "open",
        "Solution": "Upgrade OpenSSH..."
      }
    ],
    "splunk": [
      {
        "Risk Score": 9.2,
        "Rule Name": "Brute Force Attempt",
        "Status": "open"
      }
    ],
    "defender": [
      {
        "Severity": "High",
        "Title": "Mimikatz execution",
        "Status": "open"
      }
    ]
  }
}
```

### 4. Sending to AI Analysis
* The structured payload is appended to the `ANALYSIS_SYSTEM_PROMPT` containing specific cybersecurity analyst context and scoring rules.
* The combined prompt is dispatched to the **DGX Spark Server** model endpoint (`meta-llama/Llama-3.1-8B-Instruct` or similar) via an HTTP API request.

### 5. Response Extraction & Rendering
* The client extracts the JSON block from the model's raw text response.
* Variables such as `overall_risk_score` (between 0.0 and 10.0), `overall_priority_level`, and `ai_summary` are parsed and normalized.
* The dashboard displays these AI-analyzed insights dynamically, with risk scores rounded to 1 decimal place, and renders the executive summaries directly in the sticky asset detail panel.

## Installation

### 1. Clone the repository

```bash id="rajat5"
git clone https://gitlab-gov.futrend-nlm.com/futrend-inc/ai-security-monitoring-project.git
cd ai-security-monitoring-project
```

### 2. Install dependencies

```bash id="c1buyt"
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the root directory and add the following:

```env id="xhpbwe"
DGX_SPARK_SERVER_ENDPOINT_NAME="your-endpoint-name"
DGX_SPARK_SERVER_ENDPOINT_LABEL="meta-llama/Llama-3.3-70B-Instruct-4bit"
AWS_REGION="us-gov-west-1"
AI_ANALYSIS_BATCH_SIZE=1
```

### Environment Variables

| Variable                         | Description                                      |
| -------------------------------- | ------------------------------------------------ |
| DGX_SPARK_SERVER_ENDPOINT_NAME          | DGX Spark Server endpoint used for dashboard AI calls   |
| DGX_SPARK_SERVER_ENDPOINT_LABEL         | Friendly label for the configured endpoint              |
| AWS_REGION                              | AWS region for the DGX Spark Server runtime client      |
| AI_ANALYSIS_BATCH_SIZE                  | Controls batch size for AI processing                   |
| DGX_SPARK_SERVER_MAX_NEW_TOKENS         | Optional max tokens sent to the endpoint                |
| DGX_SPARK_SERVER_TEMPERATURE            | Optional generation temperature                         |
| DGX_SPARK_SERVER_READ_TIMEOUT_SECONDS   | Optional DGX Spark Server read timeout override         |
| DGX_SPARK_SERVER_CONNECT_TIMEOUT_SECONDS| Optional DGX Spark Server connect timeout override      |

Raw model responses are appended to `security_dashboard/data/raw_llm_responses.txt`.
The dashboard does not generate per-run result CSVs; use the UI Export CSV button when you want to export the current table state.
AI analysis starts fresh each time you run the app.

## Usage

Run the application:

```bash id="y3tkzm"
python app.py
```


## Dashboard Overview

The dashboard includes:

* KPIs: High-level risk metrics
* Asset Table: Searchable and filterable inventory
* Detail Panel: Drill-down view for individual assets
* SLA Aging: Tracks remediation timelines
* AI Insights: Automated analysis of security posture
* AI Chat: Interactive assistant for querying data

## Contributing

Contributions are welcome.

To contribute:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a merge request
