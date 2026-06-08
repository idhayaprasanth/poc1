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
