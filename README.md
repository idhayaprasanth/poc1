# AI Security Monitoring Project

A unified cybersecurity monitoring dashboard built with Python and Dash. This project aggregates multiple security data sources (vulnerabilities, threats, logs, and patch status) into a centralized asset inventory. Risk scoring and remediation recommendations are generated using Ollama (local LLM), and the results are presented through an analyst-friendly interface with actionable insights.

## Features

* Unified asset inventory from multiple data sources
* AI-driven risk scoring (powered by Ollama)
* AI-generated remediation recommendations
* KPI overview for quick situational awareness
* Interactive data table with filtering
* Asset detail panel for deeper analysis
* SLA aging analysis
* AI-generated security insights
* Integrated AI chat assistant

## Installation

### 1. Prerequisites

Before starting, ensure you have:
- Python 3.8 or higher
- Ollama installed and running locally
- A compatible LLM model pulled (e.g., `neural-chat`, `mistral`)

To set up Ollama:
```bash
# Install Ollama (visit https://ollama.ai/)
# Start the Ollama service
ollama serve

# In another terminal, pull a model
ollama pull neural-chat
```

### 2. Clone the repository

```bash id="rajat5"
git clone https://gitlab-gov.futrend-nlm.com/futrend-inc/ai-security-monitoring-project.git
cd ai-security-monitoring-project
```

### 3. Install dependencies

```bash id="c1buyt"
pip install -r requirements.txt
```

## Configuration

Create a `.env` file in the root directory and add the following:

```env id="xhpbwe"
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat
AI_ANALYSIS_BATCH_SIZE=1
```

### Environment Variables

| Variable               | Description                                  | Default |
| ---------------------- | -------------------------------------------- | ------- |
| OLLAMA_BASE_URL        | Ollama server base URL                       | http://localhost:11434 |
| OLLAMA_MODEL           | Ollama model name (neural-chat, mistral, llama2, etc.) | neural-chat |
| AI_ANALYSIS_BATCH_SIZE | Controls batch size for AI processing        | 1 |
| ANALYSIS_PROMPT_TEMPLATE_VERSION | Asset analysis template version (1.0 or 1.1) | 1.1 |
| CHATBOT_PROMPT_TEMPLATE_VERSION | Chatbot template version | 1.0 |

## Usage

Ensure Ollama is running before starting the dashboard:

```bash
# Terminal 1: Start Ollama (if not already running)
ollama serve

# Terminal 2: Run the application
python app.py
```

The dashboard will be available at `http://localhost:8050`


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
