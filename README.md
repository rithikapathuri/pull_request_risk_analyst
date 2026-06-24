# Pull Request Risk Analyst

## Goal
A context-aware Pull Request gatekeeper designed to eliminate "alert fatigue" in security scanning. 

Instead of blindly flagging every vulnerable dependency in a repository, this tool combines **targeted static parsing**, **blast radius calculation**, and **reachability analysis** to determine if the specific code changed in a PR actually calls a vulnerable function. It assigns a deterministic risk score to every PR and uses LLM-powered triage to provide actionable remediation steps.

## How to Run

### 1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

### 2. **Configure Environment:**

Create a .env file in the root directory and add your API keys:
```bash
GITHUB_TOKEN=""
GEMINI_API_KEY=""
NVD_API_KEY=""
```

### 3. **Start the API Server:**

From the root of the project (/), run the FastAPI development server:
```bash
uvicorn backend.main:app --reload --port 8000
```