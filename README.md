# PR Risk Autopilot

A pull request security intelligence system that goes beyond dependency scanning. Instead of flagging every vulnerable package in a repository, it determines whether the specific code changed in a PR actually reaches a vulnerable function, eliminating the false positives that cause alert fatigue in real security workflows.

**Live:** https://pull-request-risk-analyst.vercel.app

---

## How it works

Enter the owner, repository name, and PR number for any public GitHub repository. The system runs a seven-stage pipeline:

1. **Ingestion** fetches the PR diff, changed files, and dependency manifests from the GitHub REST API. Compares dependency manifests between the base and head commits to identify packages added by this PR specifically.

2. **Diff-aware parsing** extracts only the changed line ranges from the unified diff rather than scanning entire files. Runs Python's AST walker over those ranges to detect dangerous patterns precisely (eval, pickle.loads, yaml.load without Loader, subprocess with shell=True). Falls back to regex for JavaScript and TypeScript. Also scans deleted lines for removed security controls, a deleted check_permission() call is flagged as high-risk even when no new code is added.

3. **IaC scanning** separately scans Dockerfiles, GitHub Actions workflows, and Kubernetes manifests for misconfigurations: privileged containers, root user, secrets in environment variables, and curl-pipe-bash patterns.

4. **Graph building** constructs a file dependency graph and function call graph using NetworkX. For non-Python repos where call relationships are not parseable, uses the file graph as a fallback so blast radius is never zero for large PRs.

5. **CVE matching** queries OSV.dev concurrently for every dependency, extracting CVSS scores. New packages added by the PR are checked for typosquatting via edit distance against a list of commonly abused package names.

6. **Reachability analysis** runs DFS traversal from each changed function through the call graph to check whether any execution path reaches a known-vulnerable function in a flagged dependency. Non-reachable CVEs are discounted by 85% rather than dropped, the package is still present even if not currently called.

7. **Risk scoring** applies a deterministic weighted formula across four components: change severity (lines changed, weighted 2.5x for sensitive paths), blast radius, security signals, and dependency risk. No LLM is involved in scoring. Deletion signals score independently from addition signals to prevent them being averaged down by count. An auth_check_removed signal enforces a minimum score floor of 65.

An optional Gemini Flash chain then runs three sequential prompts: risk category classification, targeted explanation, and fix recommendations, with the actual diff patches included so it can reason about removed code in context.

---

## Stack

**Backend** Python, FastAPI, NetworkX, httpx, Pydantic, Tenacity  
**LLM** Gemini 1.5 Flash via google-genai SDK  
**CVE data** OSV.dev (no API key required)  
**Frontend** React, Vite, Tailwind CSS, Cytoscape.js  
**Deployment** Render (backend), Vercel (frontend)

---

## Running locally

**1. Clone and create a virtual environment**
```bash
cd pull_request_risk_analyst
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure environment variables**

Create a `.env` file in the project root:
```
GITHUB_TOKEN=your_token_here
GEMINI_API_KEY=your_key_here
NVD_API_KEY=
APP_ENV=development
```

- `GITHUB_TOKEN` generate at github.com/settings/tokens with public_repo scope. Without it you get 60 API requests/hour; with it, 5000.
- `GEMINI_API_KEY` generate at aistudio.google.com. Free tier, no credit card required.
- `NVD_API_KEY` optional. OSV.dev is the primary CVE source and needs no key.

**4. Start the backend**
```bash
uvicorn backend.main:app --reload --port 8000
```

**5. Start the frontend**
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The Vite dev server proxies `/api/*` to the backend automatically.

**6. Run the test suite**
```bash
pytest tests/ -v
```

---

## Benchmark

The system includes an evaluation suite that runs the full pipeline against known CVE-affected PRs and reports precision and recall:

```bash
python -m backend.benchmark           # no LLM, fast
python -m backend.benchmark --llm     # full pipeline
python -m backend.benchmark --cases 2 # quick smoke test
```

Results are saved to `data/benchmark/latest_results.json`.

---

## Project structure

```
pull_request_risk_analyst/
├── backend/
│   ├── main.py          FastAPI app, routes, pipeline orchestration
│   ├── config.py        Settings, scoring weights, env vars
│   ├── models.py        Pydantic models shared across all modules
│   ├── github.py        GitHub API ingestion, diff parsing, dep manifest parsers
│   ├── parser.py        AST parser, security signal detection, IaC scanning
│   ├── graph.py         NetworkX graph builder, blast radius BFS
│   ├── reachability.py  Call-path DFS, vulnerable function lookup
│   ├── cve.py           OSV.dev CVE matching, typosquatting detection
│   ├── scorer.py        Deterministic risk formula
│   ├── llm.py           Gemini chain: triage, explanation, recommendations
│   └── benchmark.py     Precision/recall eval runner
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── hooks/useAnalysis.js
│       └── components/
│           ├── SearchForm.jsx
│           ├── PRMeta.jsx
│           ├── RiskScore.jsx
│           ├── AIPanel.jsx
│           ├── BlastRadius.jsx
│           ├── SignalsTable.jsx
│           ├── CVETable.jsx
│           └── CallGraph.jsx
├── tests/
│   ├── test_github.py
│   ├── test_parser.py
│   └── test_scorer.py
├── data/benchmark/ground_truth.json
├── render.yaml
└── requirements.txt
```