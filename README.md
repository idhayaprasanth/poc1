# AI Security Monitoring Project

A unified cybersecurity monitoring dashboard built with Python and Dash. This project aggregates multiple security data sources (vulnerabilities, threats, logs, and patch status) into a centralized asset inventory. Risk scoring and remediation recommendations are generated using an AWS SageMaker-hosted model, and the results are presented through an analyst-friendly interface with actionable insights.

## Features

* Unified asset inventory from multiple data sources
* AI-driven risk scoring (powered by AWS SageMaker)
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
SAGEMAKER_ENDPOINT_NAME="your-sagemaker-endpoint-name"
AWS_REGION="us-east-1"
AI_ANALYSIS_BATCH_SIZE=1
```

### Environment Variables

| Variable               | Description                                  |
| ---------------------- | -------------------------------------------- |
| SAGEMAKER_ENDPOINT_NAME| Deployed SageMaker endpoint name             |
| AWS_REGION             | AWS region for SageMaker runtime (optional)  |
| AI_ANALYSIS_BATCH_SIZE | Controls batch size for AI processing        |

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
