# PR Risk Analyst

## Overview

PR Risk Analyst is a pull request security analysis system that determines whether code changes introduce *reachable* vulnerabilities in a codebase.

It analyzes what changed in a pull request and evaluates whether those changes can realistically reach vulnerable functions during execution. The goal is to reduce false positives from traditional dependency scanning and help engineers focus on security risks that are actually exploitable.

**Live:** https://pull-request-risk-analyst.vercel.app

---

## Problem Context

Most security tools evaluate vulnerabilities at the dependency level without understanding whether the vulnerable code is actually reachable from the changes introduced in a pull request.

This leads to findings that are technically valid but not actionable, which contributes to alert fatigue in real engineering workflows.

This project explores contextual risk analysis based on actual code execution paths, where a vulnerability only matters if it can be reached from modified code.

---

## System Architecture

The system is implemented as a multi-stage analysis pipeline that processes pull requests from ingestion through risk scoring.

### 1. Ingestion
Fetches pull request metadata from the GitHub API, including diffs, changed files, and dependency manifests. It also compares dependency files between commits to identify newly introduced packages.

### 2. Diff-aware parsing
Analyzes only modified sections of code instead of scanning entire files. Uses Python AST parsing to detect risky patterns such as:
- eval
- pickle.loads
- unsafe YAML loading
- subprocess calls with shell execution enabled

For JavaScript and TypeScript, regex-based detection is used. Deleted lines are also analyzed to capture removed security checks.

### 3. Infrastructure-as-Code scanning
Scans Dockerfiles, GitHub Actions workflows, and Kubernetes manifests for misconfigurations such as:
- privileged containers
- running as root
- exposed secrets in environment variables
- unsafe shell execution patterns

### 4. Dependency graph construction
Builds file-level and function-level dependency graphs using NetworkX. When full call graph resolution is not possible, a file-level graph is used to preserve cross-module relationships.

### 5. CVE matching
Queries OSV.dev for known vulnerabilities in dependencies and maps them to CVSS severity scores. Newly introduced packages are checked for potential typosquatting using string similarity comparisons.

### 6. Reachability analysis
Performs graph traversal from modified functions to determine whether execution paths can reach vulnerable functions in dependencies. Vulnerabilities that are not reachable are down-weighted rather than removed entirely.

### 7. Risk scoring
Applies a deterministic scoring function that combines:
- severity of code changes
- blast radius of modified components
- static security signals
- dependency risk

The scoring logic is fully deterministic and does not rely on LLMs. This ensures consistent results across runs and avoids variability in risk classification.

---

## Optional explanation layer (LLM)

An optional Gemini Flash-based module provides:
- risk categorization
- natural language explanation
- remediation suggestions

This layer is used only for explanation and does not affect the underlying risk score.

---

## Stack

**Backend**
Python, FastAPI, NetworkX, httpx, Pydantic, Tenacity

**Frontend**
React, Vite, Tailwind CSS, Cytoscape.js

**Security data**
OSV.dev for CVE data

**LLM layer**
Gemini 2.5 Flash via google-genai SDK

**Deployment**
Render (backend), Vercel (frontend)

---

## Running locally

### 1. Clone and set up environment
```bash
cd pull_request_risk_analyst
python -m venv venv
source venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Create .env file and add environment variables
```bash
GITHUB_TOKEN=your_token_here
GEMINI_API_KEY=your_key_here
NVD_API_KEY=your_key_here
```

### 4. Run backend
```bash
uvicorn backend.main:app --reload --port 8000
```

### 5. Run frontend
```bash
cd frontend
npm install
npm run dev
```

### 6. Run benchmark
```bash
python -m backend.benchmark
python -m backend.benchmark --llm
python -m backend.benchmark --cases 2
```

Benchmark results are stored in data/benchmark/latest_results.json

### 7. Project Structure
```bash
backend/
  main.py
  config.py
  models.py
  github.py
  parser.py
  graph.py
  reachability.py
  cve.py
  scorer.py
  llm.py
  benchmark.py

frontend/
  src/
    App.jsx
    hooks/useAnalysis.js
    components/
      SearchForm.jsx
      PRMeta.jsx
      RiskScore.jsx
      AIPanel.jsx
      BlastRadius.jsx
      SignalsTable.jsx
      CVETable.jsx
      CallGraph.jsx

tests/
  test_github.py
  test_parser.py
  test_scorer.py
```

