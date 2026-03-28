"""
Graders for the SOC Analyst environment tasks.

Each grader takes the final environment state and produces a score between 0.0 and 1.0.
Scores are deterministic: same trajectory -> same score.
"""

from typing import Any, Dict, List, Optional

# Severity weights for reward shaping
SEVERITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}


def grade_task1_triage(
    classifications: Dict[str, str],
    ground_truth: Dict[str, str],
    alerts: List[Dict[str, Any]],
    step_count: int,
    max_steps: int,
) -> float:
    """
    Grade Task 1: Alert Triage.

    Scoring:
    - Classification accuracy weighted by severity (70%)
    - Efficiency bonus for fewer steps (15%)
    - Completion bonus for classifying all alerts (15%)
    """
    if not ground_truth:
        return 0.0

    # --- Classification accuracy (70%) ---
    total_weight = 0.0
    correct_weight = 0.0
    for alert in alerts:
        aid = alert["alert_id"]
        severity = alert.get("severity_hint", "medium")
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        total_weight += weight

        if aid in classifications:
            agent_class = classifications[aid]
            truth = ground_truth.get(aid, "")
            if agent_class == truth:
                correct_weight += weight
            elif agent_class == "needs_investigation" and truth == "true_positive":
                correct_weight += weight * 0.5

    accuracy_score = (correct_weight / total_weight) if total_weight > 0 else 0.0

    # --- Efficiency bonus (15%) ---
    optimal_steps = len(alerts)
    if step_count <= optimal_steps:
        efficiency_score = 1.0
    else:
        efficiency_score = max(
            0.0, 1.0 - (step_count - optimal_steps) / (max_steps - optimal_steps)
        )

    # --- Completion bonus (15%) ---
    classified_count = sum(1 for a in alerts if a["alert_id"] in classifications)
    completion_score = classified_count / len(alerts) if alerts else 0.0

    final_score = (
        0.70 * accuracy_score + 0.15 * efficiency_score + 0.15 * completion_score
    )
    return round(min(1.0, max(0.0, final_score)), 4)


def grade_task2_investigation(
    classifications: Dict[str, str],
    ground_truth: Dict[str, str],
    alerts: List[Dict[str, Any]],
    actions_taken: List[str],
    queries_made: int,
    containment_actions: List[str],
    escalation_actions: List[str],
    dismissal_actions: List[str],
    step_count: int,
    max_steps: int,
) -> float:
    """
    Grade Task 2: Incident Investigation.

    Scoring:
    - Correct diagnosis / classification (35%)
    - Appropriate response action (25%)
    - Investigation quality - queried relevant context (20%)
    - Efficiency - didn't waste queries (10%)
    - Completion (10%)
    """
    # --- Classification accuracy (35%) ---
    total_weight = 0.0
    correct_weight = 0.0
    for alert in alerts:
        aid = alert["alert_id"]
        severity = alert.get("severity_hint", "medium")
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        total_weight += weight
        if aid in classifications:
            if classifications[aid] == ground_truth.get(aid, ""):
                correct_weight += weight
    accuracy_score = (correct_weight / total_weight) if total_weight > 0 else 0.0

    # --- Response action quality (25%) ---
    response_score = 0.0
    primary_alert = next((a for a in alerts if a["alert_id"] == "INC-001"), None)
    if primary_alert:
        if (
            "contain:INC-001" in containment_actions
            or "contain:INC-002" in containment_actions
        ):
            response_score += 0.6
        if (
            "escalate:INC-001" in escalation_actions
            or "escalate:INC-002" in escalation_actions
        ):
            response_score += 0.3
        if "dismiss:INC-003" in dismissal_actions:
            response_score += 0.1
    response_score = min(1.0, response_score)

    # --- Investigation quality (20%) ---
    investigation_score = 0.0
    useful_queries = 0
    for action in actions_taken:
        if "query_context" in action:
            if any(
                qt in action for qt in ["threat_intel", "network_logs", "user_profile"]
            ):
                if "INC-001" in action or "INC-002" in action:
                    useful_queries += 1
    if useful_queries >= 2:
        investigation_score = 1.0
    elif useful_queries == 1:
        investigation_score = 0.6
    else:
        investigation_score = 0.2

    # --- Efficiency (10%) ---
    optimal_steps = 7
    if step_count <= optimal_steps:
        efficiency_score = 1.0
    else:
        efficiency_score = max(
            0.0, 1.0 - (step_count - optimal_steps) / (max_steps - optimal_steps)
        )

    # --- Completion (10%) ---
    classified_count = sum(1 for a in alerts if a["alert_id"] in classifications)
    has_response = (
        len(containment_actions) + len(escalation_actions) + len(dismissal_actions) > 0
    )
    completion_score = (classified_count / len(alerts)) * 0.7 + (
        0.3 if has_response else 0.0
    )

    final_score = (
        0.35 * accuracy_score
        + 0.25 * response_score
        + 0.20 * investigation_score
        + 0.10 * efficiency_score
        + 0.10 * completion_score
    )
    return round(min(1.0, max(0.0, final_score)), 4)


def grade_task3_correlation(
    classifications: Dict[str, str],
    ground_truth: Dict[str, str],
    alerts: List[Dict[str, Any]],
    correlated_chains: List[List[str]],
    actual_chain_alerts: List[str],
    report_submitted: bool,
    report_text: str,
    actions_taken: List[str],
    containment_actions: List[str],
    step_count: int,
    max_steps: int,
) -> float:
    """
    Grade Task 3: Multi-Alert Correlation.

    Scoring:
    - Attack chain identification (30%)
    - Classification accuracy (20%)
    - Incident report quality (20%)
    - Response prioritization (15%)
    - Noise filtering (15%)
    """
    # --- Attack chain identification (30%) ---
    chain_score = 0.0
    if correlated_chains:
        best_match = 0.0
        actual_set = set(actual_chain_alerts)
        for chain in correlated_chains:
            chain_set = set(chain)
            if not chain_set:
                continue
            precision = len(chain_set & actual_set) / len(chain_set) if chain_set else 0
            recall = len(chain_set & actual_set) / len(actual_set) if actual_set else 0
            if precision + recall > 0:
                f1 = 2 * (precision * recall) / (precision + recall)
            else:
                f1 = 0.0
            best_match = max(best_match, f1)
        chain_score = best_match

    # --- Classification accuracy (20%) ---
    total_weight = 0.0
    correct_weight = 0.0
    for alert in alerts:
        aid = alert["alert_id"]
        severity = alert.get("severity_hint", "medium")
        weight = SEVERITY_WEIGHTS.get(severity, 1.0)
        total_weight += weight
        if aid in classifications:
            if classifications[aid] == ground_truth.get(aid, ""):
                correct_weight += weight
    accuracy_score = (correct_weight / total_weight) if total_weight > 0 else 0.0

    # --- Report quality (20%) ---
    report_score = 0.0
    if report_submitted and report_text:
        report_lower = report_text.lower()
        key_elements = {
            "attack_stages": any(
                w in report_lower
                for w in [
                    "reconnaissance",
                    "recon",
                    "scanning",
                    "initial access",
                    "phishing",
                    "lateral movement",
                    "exfiltration",
                    "kill chain",
                    "attack chain",
                ]
            ),
            "threat_actor": any(
                w in report_lower
                for w in [
                    "apt",
                    "cobalt strike",
                    "c2",
                    "command and control",
                    "beacon",
                    "attacker",
                    "threat actor",
                    "adversary",
                ]
            ),
            "impact": any(
                w in report_lower
                for w in [
                    "financial",
                    "data",
                    "database",
                    "exfiltrat",
                    "stolen",
                    "compromised",
                    "breach",
                ]
            ),
            "affected_hosts": any(
                w in report_lower
                for w in [
                    "10.0.1.15",
                    "10.0.2.10",
                    "eng-ws-015",
                    "fin-ws-010",
                    "jsmith",
                    "agarcia",
                    "engineering",
                    "finance",
                ]
            ),
            "recommendations": any(
                w in report_lower
                for w in [
                    "contain",
                    "isolat",
                    "block",
                    "remediat",
                    "password reset",
                    "forensic",
                    "incident response",
                ]
            ),
        }
        elements_found = sum(1 for v in key_elements.values() if v)
        report_score = elements_found / len(key_elements)

    # --- Response prioritization (15%) ---
    response_score = 0.0
    critical_containments = ["contain:MC-004", "contain:MC-009", "contain:MC-008"]
    contained_critical = sum(
        1 for c in critical_containments if c in containment_actions
    )
    response_score = min(1.0, contained_critical / 2.0)

    # --- Noise filtering (15%) ---
    noise_alerts = [
        a["alert_id"] for a in alerts if a.get("ground_truth") == "false_positive"
    ]
    correctly_dismissed = 0
    for aid in noise_alerts:
        if classifications.get(aid) == "false_positive":
            correctly_dismissed += 1
    noise_score = correctly_dismissed / len(noise_alerts) if noise_alerts else 0.0

    final_score = (
        0.30 * chain_score
        + 0.20 * accuracy_score
        + 0.20 * report_score
        + 0.15 * response_score
        + 0.15 * noise_score
    )
    return round(min(1.0, max(0.0, final_score)), 4)


def compute_step_reward(
    action_type: str,
    alert: Optional[Dict[str, Any]],
    classification: Optional[str],
    ground_truth: Optional[str],
    severity: str = "medium",
    is_useful_query: bool = False,
    step_count: int = 0,
    max_steps: int = 20,
) -> float:
    """
    Compute per-step reward for reward shaping.

    Provides partial progress signals rather than sparse end-of-episode rewards.
    """
    reward = 0.0
    weight = SEVERITY_WEIGHTS.get(severity, 1.0)

    if action_type == "classify" and classification and ground_truth:
        if classification == ground_truth:
            reward = 0.15 * weight
        elif (
            classification == "needs_investigation" and ground_truth == "true_positive"
        ):
            reward = 0.05 * weight
        else:
            reward = -0.10 * weight
            if ground_truth == "true_positive" and classification == "false_positive":
                reward -= 0.15 * weight

    elif action_type == "query_context":
        if is_useful_query:
            reward = 0.05
        else:
            reward = -0.02

    elif action_type == "contain":
        if ground_truth == "true_positive":
            reward = 0.20 * weight
        else:
            reward = -0.10

    elif action_type == "escalate":
        if ground_truth == "true_positive":
            reward = 0.10 * weight
        else:
            reward = -0.05

    elif action_type == "dismiss":
        if ground_truth == "false_positive":
            reward = 0.05
        else:
            reward = -0.20 * weight

    elif action_type == "correlate":
        reward = 0.02

    elif action_type == "submit_report":
        reward = 0.05

    elif action_type == "noop":
        reward = -0.01

    # Time pressure: slight decay for taking too long
    time_decay = -0.005 * (step_count / max_steps)
    reward += time_decay

    return round(reward, 4)
