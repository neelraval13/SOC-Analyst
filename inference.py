"""
Inference Script for SOC Analyst Environment
=============================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables
"""

import json
import os
import re
import textwrap
from typing import Any, Dict, List

import requests
from openai import OpenAI
from openai.types.chat import ChatCompletionMessageParam

# ============================================================================
# Configuration
# ============================================================================

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY", "")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.1-8B-Instruct")
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")

TEMPERATURE = 0.2
MAX_TOKENS = 500

# Task configurations
TASKS = [
    {"task_id": "soc_triage_easy", "max_steps": 10, "name": "Easy: Alert Triage"},
    {
        "task_id": "soc_investigate_medium",
        "max_steps": 15,
        "name": "Medium: Incident Investigation",
    },
    {
        "task_id": "soc_correlate_hard",
        "max_steps": 25,
        "name": "Hard: Multi-Alert Correlation",
    },
]

# ============================================================================
# System Prompts
# ============================================================================

SYSTEM_PROMPT_TRIAGE = textwrap.dedent("""
You are a SOC (Security Operations Center) Tier-1 analyst. Your job is to classify security alerts.

You will be given alerts. For each alert, classify it as:
- true_positive: A real security threat that needs action
- false_positive: A benign event that triggered incorrectly
- needs_investigation: Ambiguous, requires deeper analysis

Respond with EXACTLY ONE JSON action per message. No extra text.

Action format:
{"action_type": "classify", "alert_id": "<ID>", "classification": "<label>"}

Or to query context first:
{"action_type": "query_context", "alert_id": "<ID>", "query_type": "<user_profile|network_logs|threat_intel|asset_info>"}

Classify all alerts to complete the task. Prioritize critical/high severity alerts.
Think about: Is the source IP known malicious? Is the behavior normal for this user/system?
""").strip()

SYSTEM_PROMPT_INVESTIGATE = textwrap.dedent("""
You are a SOC Tier-2 analyst investigating suspicious security alerts.

Your workflow:
1. Review the alerts
2. Query context to gather evidence (threat_intel, network_logs, user_profile, asset_info)
3. Classify each alert
4. Take response actions (escalate, contain, or dismiss)

Respond with EXACTLY ONE JSON action per message. No extra text.

Available actions:
{"action_type": "query_context", "alert_id": "<ID>", "query_type": "<user_profile|network_logs|threat_intel|asset_info>"}
{"action_type": "classify", "alert_id": "<ID>", "classification": "<true_positive|false_positive|needs_investigation>"}
{"action_type": "escalate", "alert_id": "<ID>", "reason": "<why>"}
{"action_type": "contain", "alert_id": "<ID>", "reason": "<why>"}
{"action_type": "dismiss", "alert_id": "<ID>", "reason": "<why>"}

Investigate before classifying. Contain compromised hosts. Dismiss false positives.
""").strip()

SYSTEM_PROMPT_CORRELATE = textwrap.dedent("""
You are a SOC Tier-3 analyst / Incident Commander analyzing multiple security alerts.

Some alerts are noise, but others may be stages of a coordinated attack campaign (kill chain).
Your job:
1. Query context for suspicious alerts
2. Classify all alerts
3. Identify related alerts and correlate them into an attack chain
4. Take containment actions on critical threats
5. Submit an incident report

Respond with EXACTLY ONE JSON action per message. No extra text.

Available actions:
{"action_type": "query_context", "alert_id": "<ID>", "query_type": "<user_profile|network_logs|threat_intel|asset_info>"}
{"action_type": "classify", "alert_id": "<ID>", "classification": "<true_positive|false_positive|needs_investigation>"}
{"action_type": "correlate", "alert_ids": ["<ID1>", "<ID2>", ...]}
{"action_type": "contain", "alert_id": "<ID>", "reason": "<why>"}
{"action_type": "dismiss", "alert_id": "<ID>", "reason": "<why>"}
{"action_type": "escalate", "alert_id": "<ID>", "reason": "<why>"}
{"action_type": "submit_report", "report": "<incident report text describing the attack chain, affected systems, and recommendations>"}

Look for patterns: same source IPs across alerts, temporal progression, attack chain stages
(recon -> initial access -> execution -> lateral movement -> exfiltration).
""").strip()

SYSTEM_PROMPTS = {
    "soc_triage_easy": SYSTEM_PROMPT_TRIAGE,
    "soc_investigate_medium": SYSTEM_PROMPT_INVESTIGATE,
    "soc_correlate_hard": SYSTEM_PROMPT_CORRELATE,
}


# ============================================================================
# Environment interaction (HTTP-based)
# ============================================================================


def env_reset(task_id: str, seed: int = 42) -> Dict[str, Any]:
    """Reset the environment for a specific task."""
    resp = requests.post(
        f"{ENV_BASE_URL}/reset",
        json={"seed": seed, "task_id": task_id},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def env_step(action: Dict[str, Any]) -> Dict[str, Any]:
    """Take a step in the environment."""
    resp = requests.post(
        f"{ENV_BASE_URL}/step",
        json=action,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def env_state() -> Dict[str, Any]:
    """Get current environment state."""
    resp = requests.get(f"{ENV_BASE_URL}/state", timeout=30)
    resp.raise_for_status()
    return resp.json()


# ============================================================================
# LLM interaction
# ============================================================================


def build_user_prompt(observation: Dict[str, Any], step: int) -> str:
    """Build a user prompt from the environment observation."""
    task_desc = observation.get("task_description", "")
    alerts = observation.get("alerts", [])
    feedback = observation.get("action_feedback", "")
    context = observation.get("context_response", "")
    classifications = observation.get("classifications_made", {})
    actions = observation.get("actions_taken", [])
    available = observation.get("available_actions", [])
    max_steps = observation.get("max_steps", 20)
    score = observation.get("score_so_far", 0.0)

    # Format alerts concisely
    alert_lines = []
    for a in alerts:
        classified = classifications.get(a.get("alert_id", ""), None)
        status = f" [CLASSIFIED: {classified}]" if classified else " [UNCLASSIFIED]"
        alert_lines.append(
            f"  [{a.get('alert_id')}] severity={a.get('severity_hint')} "
            f"type={a.get('alert_type')} src={a.get('source_ip')} "
            f"dst={a.get('dest_ip')} rule={a.get('rule_name')}{status}\n"
            f"    Description: {a.get('description', '')}"
        )

    alerts_text = "\n".join(alert_lines) if alert_lines else "  (none)"

    # Recent actions (last 5)
    recent_actions = actions[-5:] if actions else ["(none)"]

    prompt = textwrap.dedent(f"""
Step {step}/{max_steps} | Score so far: {score:.3f}
Task: {task_desc}

=== ALERTS ===
{alerts_text}

=== LAST FEEDBACK ===
{feedback}
""").strip()

    if context:
        prompt += f"\n\n=== CONTEXT QUERY RESULT ===\n{context}"

    prompt += "\n\n=== RECENT ACTIONS ===\n" + "\n".join(recent_actions)
    prompt += f"\n\nAvailable actions: {', '.join(available)}"
    prompt += "\n\nRespond with ONE JSON action:"

    return prompt


def parse_action(response_text: str) -> Dict[str, Any]:
    """Parse LLM response into an action dict."""
    if not response_text:
        return {
            "action_type": "classify",
            "alert_id": "ALT-001",
            "classification": "needs_investigation",
        }

    # Try to find JSON in response
    text = response_text.strip()

    # Remove markdown code blocks if present
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    # Try to find JSON object
    json_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if json_match:
        try:
            action = json.loads(json_match.group())
            if "action_type" in action:
                return action
        except json.JSONDecodeError:
            pass

    # Fallback: try to parse the whole thing
    try:
        action = json.loads(text)
        if isinstance(action, dict) and "action_type" in action:
            return action
    except json.JSONDecodeError:
        pass

    # Last resort fallback
    return {
        "action_type": "classify",
        "alert_id": "ALT-001",
        "classification": "needs_investigation",
    }


# ============================================================================
# Main inference loop
# ============================================================================


def run_task(client: OpenAI, task_config: Dict[str, Any]) -> float:
    """Run a single task and return the final score."""
    task_id = task_config["task_id"]
    max_steps = task_config["max_steps"]
    task_name = task_config["name"]

    print(f"\n{'=' * 60}")
    print(f"Running: {task_name}")
    print(f"Task ID: {task_id}")
    print(f"{'=' * 60}")

    # --- Required structured output: task start ---
    print(f"[START] task={task_id}", flush=True)

    # Reset environment
    obs = env_reset(task_id=task_id, seed=42)
    system_prompt = SYSTEM_PROMPTS[task_id]

    messages: List[ChatCompletionMessageParam] = [
        {"role": "system", "content": system_prompt},
    ]

    final_score = 0.0
    completed_step = 0

    for step in range(1, max_steps + 1):
        if obs.get("done", False):
            final_score = obs.get("metadata", {}).get("final_score", 0.0)
            print(f"  Episode complete at step {step - 1}. Final score: {final_score}")
            break

        # Build user prompt
        user_prompt = build_user_prompt(obs, step)

        # Manage conversation - keep system + last 6 messages to fit context
        messages.append({"role": "user", "content": user_prompt})
        if len(messages) > 7:
            messages = [messages[0]] + messages[-6:]

        # Query LLM
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            response_text = completion.choices[0].message.content or ""
        except Exception as exc:
            print(f"  Step {step}: LLM error ({exc}). Using fallback.")
            response_text = ""

        # Parse action
        action = parse_action(response_text)
        print(
            f"  Step {step}: {action.get('action_type', '?')} -> {action.get('alert_id', '')}"
        )

        # Add assistant message to history
        messages.append({"role": "assistant", "content": response_text})

        # Step environment
        try:
            obs = env_step(action)
        except Exception as exc:
            print(f"  Step {step}: Environment error ({exc}). Stopping.")
            break

        reward = obs.get("reward", 0) or 0.0
        score_so_far = obs.get("score_so_far", 0.0) or 0.0
        if reward is not None:
            print(f"    Reward: {reward:.4f} | Score: {score_so_far:.4f}")

        # --- Required structured output: per-step ---
        print(f"[STEP] step={step} reward={reward:.4f}", flush=True)
        completed_step = step

    # Get final score from observation if episode ended
    if obs.get("done", False):
        final_score = obs.get("metadata", {}).get("final_score", final_score)
    else:
        try:
            final_score = obs.get("reward", 0.0) or 0.0
        except Exception:
            pass

    print(f"  Final Score: {final_score:.4f}")

    # --- Required structured output: task end ---
    print(f"[END] task={task_id} score={final_score:.4f} steps={completed_step}", flush=True)

    return final_score


def main():
    """Run baseline inference across all 3 tasks."""
    print("SOC Analyst Environment - Baseline Inference")
    print(f"API Base URL: {API_BASE_URL}")
    print(f"Model: {MODEL_NAME}")
    print(f"Environment: {ENV_BASE_URL}")

    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    results = {}
    for task_config in TASKS:
        try:
            score = run_task(client, task_config)
            results[task_config["task_id"]] = score
        except Exception as exc:
            print(f"  Task {task_config['task_id']} failed: {exc}")
            results[task_config["task_id"]] = 0.0

    # Print summary
    print(f"\n{'=' * 60}")
    print("RESULTS SUMMARY")
    print(f"{'=' * 60}")
    for task_id, score in results.items():
        print(f"  {task_id}: {score:.4f}")
    avg = sum(results.values()) / len(results) if results else 0.0
    print(f"  Average: {avg:.4f}")
    print(f"{'=' * 60}")

    return results


if __name__ == "__main__":
    main()
