# Cyber Threat Intelligence & Risk Analytics Platform

A web-based cybersecurity analytics platform that collects, processes, stores, and visualizes threat intelligence data from URLhaus.

## Project Overview

The Cyber Threat Intelligence & Risk Analytics Platform transforms publicly available threat intelligence records into structured information through a Python ETL pipeline and an interactive Flask dashboard.

The platform focuses on analyzing URLs reported by URLhaus as associated with malware distribution.

## Dataset Selection

**Dataset:** URLhaus Recent URLs API  
**Source:** [URLhaus](https://urlhaus.abuse.ch/)

URLhaus was selected because it provides real-world threat intelligence records with useful attributes, including:

- Reported URLs
- Hostnames
- URL status
- Threat categories
- Date added
- Reporter information
- Tags

These attributes support data-quality analysis, status distribution, host analysis, and time-based trend exploration.

## System Architecture

The application follows an ETL-based architecture:

1. **Extract:** Retrieve recent URL records from the URLhaus API using Python Requests.
2. **Validate:** Validate incoming records using Pydantic.
3. **Transform:** Clean and process records using Pandas.
4. **Load:** Store processed records in an SQLite database.
5. **Analyze:** Perform exploratory data analysis.
6. **Visualize:** Present insights through a Flask-based web dashboard.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Requests | API data extraction |
| Pydantic | Data validation |
| Pandas | Data cleaning and analysis |
| SQLite | Database storage |
| Flask | Backend web framework |
| HTML | Dashboard structure |
| CSS | Dashboard styling |
| JavaScript | Frontend interaction |
| Chart.js | Data visualization |
| Matplotlib | Statistical charts |

## Database

The cleaned records are stored in an SQLite database:

`data/database/threat_intel.db`

The main table is `urlhaus_urls`.

## Exploratory Data Analysis (EDA)

The platform performs:

- URL status distribution analysis.
- Top 10 host analysis.
- Date-based URL record trend analysis.
- Threat-category exploration.
- Missing-value and duplicate-record analysis.
- Record-level search and filtering.

## Dashboard Features

- Total URL records.
- Online and offline URL statistics.
- Unique host count.
- URL status doughnut chart.
- Top 10 hosts bar chart.
- URL record trends line chart.
- Search by URL or hostname.
- Status and risk-level filters.
- Paginated threat records table.

## Reliability and Observability

The project incorporates:

- API retry handling.
- Previously saved data fallback when API extraction fails.
- Data validation before database insertion.
- Duplicate protection.
- Application logging.
- Database health checks.

## Risk Classification

The dashboard derives monitoring-priority labels from reported URL status:

- Online: High
- Offline: Medium
- Other or missing status: Unclassified

These labels are operational monitoring categories, not independently verified malware severity ratings.

## Project Scope

This platform analyzes threat intelligence information reported by URLhaus. It does not independently scan URLs, execute malware, block network traffic, or verify that a host has been compromised.

## Running Locally

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd cyber-threat-platform
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Create a `.env` file and add your URLhaus API credential:

```text
URLHAUS_AUTH_KEY=YOUR_API_KEY
```

Never commit `.env` or expose API credentials publicly.

### 6. Run the application

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

## Future Improvements

- Online deployment.
- Advanced threat analytics.
- Enhanced monitoring and reporting.
- Additional data sources.
- Persistent production database infrastructure.