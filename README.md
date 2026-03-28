# SOC Analyst Environment

A realistic Security Operations Center (SOC) analyst simulation built on the [OpenEnv](https://github.com/meta-pytorch/OpenEnv) framework. AI agents learn to triage security alerts, investigate incidents, and identify coordinated cyberattack campaigns.

## Why This Environment?

SOC analysts are the front line of cybersecurity defense. They process hundreds of alerts daily, with ~80% being false positives. Analyst burnout and alert fatigue are industry-wide problems. This environment models three core SOC workflows at increasing difficulty, providing a rich testbed for training and evaluating AI agents on real-world security decision-making.

## Tasks

### Task 1: Alert Triage (Easy)
- **Objective**: Classify 5 security alerts as `true_positive`, `false_positive`, or `needs_investigation`
- **Max steps**: 10
- **Grading**: Classification accuracy weighted by severity (70%), efficiency (15%), completion (15%)

### Task 2: Incident Investigation (Medium)
- **Objective**: Investigate 3 suspicious alerts by querying context (user profiles, threat intel, network logs), then classify and take response actions (escalate, contain, or dismiss)
- **Max steps**: 15
- **Grading**: Diagnosis accuracy (35%), response appropriateness (25%), investigation quality (20%), efficiency (10%), completion (10%)

### Task 3: Multi-Alert Correlation (Hard)
- **Objective**: Analyze 10 alerts (mix of a coordinated attack campaign and noise), identify the kill chain, correlate related alerts, take containment actions, and submit an incident report
- **Max steps**: 25
- **Grading**: Attack chain identification via F1 score (30%), classification accuracy (20%), report quality (20%), response prioritization (15%), noise filtering (15%)

## Action Space

| Action | Parameters | Description |
|--------|-----------|-------------|
| `classify` | `alert_id`, `classification` | Classify alert as `true_positive`, `false_positive`, or `needs_investigation` |
| `query_context` | `alert_id`, `query_type` | Query: `user_profile`, `network_logs`, `threat_intel`, `asset_info` |
| `escalate` | `alert_id`, `reason` | Escalate alert to incident response team |
| `contain` | `alert_id`, `reason` | Isolate the source host from the network |
| `dismiss` | `alert_id`, `reason` | Dismiss alert as benign |
| `correlate` | `alert_ids` | Group related alerts into an incident (Task 3) |
| `submit_report` | `report` | Submit incident report text (Task 3) |

## Observation Space

Each observation includes:
- `task_id` / `task_description`: Current task context
- `alerts`: List of active security alerts with source/dest IPs, severity, rule name, description, raw log
- `context_response`: Result of the last context query (if any)
- `action_feedback`: Feedback from the last action taken
- `classifications_made`: Map of completed classifications
- `actions_taken`: History of all actions
- `available_actions`: Valid actions for current task
- `score_so_far`: Running cumulative reward
- `step_number` / `max_steps`: Progress tracking

## Reward Design

Dense reward signals (not sparse end-of-episode):
- Correct classification: +0.15 to +0.45 (scaled by alert severity)
- Missing a true positive: -0.10 to -0.75 (harsh penalty for critical misses)
- False escalation: -0.05
- Useful context query: +0.05
- Wasted query: -0.02
- Correct containment: +0.20 to +0.60
- Time decay: -0.005 per step

Final episode score (0.0-1.0) is computed by the task grader at episode end.

## Setup & Usage

### Local Development
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install openenv-core fastapi uvicorn pydantic openai requests

# Start the server
python3 -m uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Run Baseline Inference
```bash
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export HF_TOKEN="your_huggingface_token"
export ENV_BASE_URL="http://localhost:7860"
python inference.py
```

### Docker
```bash
docker build -t soc-analyst-env .
docker run -p 7860:7860 soc-analyst-env
```

## Baseline Scores

| Task | Score | Notes |
|------|-------|-------|
| Easy: Alert Triage | ~0.45-0.55 | Reasonable classification but misses nuance |
| Medium: Investigation | ~0.30-0.40 | Often skips context queries |
| Hard: Correlation | ~0.15-0.25 | Struggles with kill chain identification |

## Project Structure
```
soc_analyst_env/
├── __init__.py
├── models.py
├── client.py
├── inference.py
├── openenv.yaml
├── pyproject.toml
├── Dockerfile
├── .dockerignore
├── README.md
└── server/
    ├── __init__.py
    ├── app.py
    ├── soc_environment.py
    ├── alerts_data.py
    ├── graders.py
    └── requirements.txt
```

## License

MIT
