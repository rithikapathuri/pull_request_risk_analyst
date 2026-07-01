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

The system is implemented as a multi-stage analysis pipeline that operates in a **Dual-Mode Architecture**: a stateless cloud webhook for instant CI/CD PR checks, and a local CLI runner for deep, repository-wide analysis.

### 1. Ingestion
Fetches pull request metadata from the GitHub API, including diffs, changed files, and dependency manifests. To guarantee parsing integrity, it fetches the full file contents locked to the immutable `head_sha`. In local CLI mode, it bypasses the network entirely, using `subprocess` to extract local Git diffs and traversing the local file system.

### 2. Diff-aware parsing
Analyzes the full source files to ensure Abstract Syntax Tree (AST) integrity, then mathematically intersects findings with the modified diff line ranges. It uses Python AST to detect risky patterns such as:
- eval
- pickle.loads
- unsafe YAML loading
- subprocess calls with shell execution enabled

Regex-based detection is used for JavaScript, TypeScript, and Go. Deleted lines are uniquely analyzed to capture the removal of critical security controls (e.g., deleted authentication checks).

### 3. Infrastructure-as-Code scanning
Scans Dockerfiles, GitHub Actions workflows, and Kubernetes manifests for misconfigurations such as:
- privileged containers
- running as root
- exposed secrets in environment variables
- unsafe shell execution patterns

### 4. Semantic Blast Radius & Graph Construction
Builds file-level and function-level dependency graphs using NetworkX. Risk impact is evaluated dynamically:
- **Cloud Mode (Semantic Analysis):** Blast radius is determined deterministically by analyzing actual file imports (e.g., `bcrypt`, `sqlalchemy`) and execution behaviors, completely ignoring fragile filename conventions.
- **Local CLI Mode (Graph Centrality):** Builds a global repository graph and uses mathematical `in_degree_centrality` to calculate an accurate blast radius based on how many modules rely on the modified code.

### 5. CVE Matching & NVD Enrichment
Queries OSV.dev for known vulnerabilities in dependencies. It then concurrently enriches these findings via the **NVD API** (using async semaphores to respect rate limits) to attach highly accurate CVSS base scores and descriptions. Newly introduced packages are also checked for potential typosquatting using string similarity edit-distance algorithms.

### 6. Reachability analysis
Performs Depth-First Search (DFS) graph traversal from modified functions to determine whether execution paths can reach vulnerable functions in dependencies. Vulnerabilities that are completely isolated are mathematically down-weighted rather than removed entirely.

### 7. Deterministic Risk Scoring
Applies a strict scoring function that mathematically combines:
- severity of code changes
- blast radius of modified components
- static security signals (heavily penalizing removed security controls)
- dependency risk (mitigated by reachability)

The scoring logic is fully deterministic and does not rely on LLMs, ensuring consistent results across runs.

---

## Optional explanation layer (LLM)

An optional Gemini Flash-based module provides:
- risk categorization
- natural language explanation
- remediation suggestions

This layer is used exclusively for human-readable synthesis and context, and it does not generate or alter the underlying risk score.

---

## Stack

**Backend**
Python, FastAPI, NetworkX, httpx, Pydantic, Tenacity, argparse

**Frontend**
React, Vite, Tailwind CSS, Cytoscape.js

**Security data**
OSV.dev, National Vulnerability Database (NVD) API

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

### 6. Run CLI -> Local Repository Mode
```bash
python -m backend.cli --repo /path/to/your/project --branch main --llm
```

### 7. Run benchmark
```bash
python -m backend.benchmark
python -m backend.benchmark --llm
python -m backend.benchmark --cases 2
```

Benchmark results are stored in data/benchmark/latest_results.json

### 8. Project Structure
```bash
backend/
  main.py
  cli.py
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

