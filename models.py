# Models for the SOC Analyst OpenEnv Environment

from typing import Dict, List, Optional, Any
from pydantic import Field
from openenv.core.env_server.types import Action, Observation, State


class SOCAction(Action):
    """Action taken by the SOC analyst agent."""

    action_type: str = Field(
        ...,
        description="Type of action: classify, query_context, escalate, contain, dismiss, correlate, submit_report",
    )
    alert_id: Optional[str] = Field(
        default=None,
        description="ID of the alert to act on",
    )
    classification: Optional[str] = Field(
        default=None,
        description="Classification label: true_positive, false_positive, needs_investigation",
    )
    query_type: Optional[str] = Field(
        default=None,
        description="Type of context query: user_profile, network_logs, threat_intel, asset_info",
    )
    alert_ids: Optional[List[str]] = Field(
        default=None,
        description="List of alert IDs to correlate together",
    )
    report: Optional[str] = Field(
        default=None,
        description="Incident report text for submit_report action",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Optional reasoning for the action",
    )


class AlertInfo(Action):
    """Individual alert information presented to the agent."""

    alert_id: str = Field(..., description="Unique alert identifier")
    timestamp: str = Field(..., description="When the alert was generated")
    source_ip: str = Field(..., description="Source IP address")
    dest_ip: str = Field(..., description="Destination IP address")
    alert_type: str = Field(
        ...,
        description="Category: malware, intrusion, insider_threat, policy_violation, system_anomaly",
    )
    severity_hint: str = Field(
        ..., description="Suggested severity: low, medium, high, critical"
    )
    rule_name: str = Field(
        ..., description="Name of the detection rule that triggered"
    )
    description: str = Field(..., description="Human-readable alert description")
    raw_log: str = Field(..., description="Simulated raw log entry")
    ground_truth: Optional[str] = Field(
        default=None,
        description="Hidden ground truth - not shown to agent",
        exclude=True,
    )
    attack_chain_id: Optional[str] = Field(
        default=None,
        description="Hidden attack chain membership - not shown to agent",
        exclude=True,
    )


class SOCObservation(Observation):
    """What the SOC analyst agent observes after each action."""

    task_id: str = Field(..., description="Current task identifier")
    task_description: str = Field(..., description="Description of the current task")
    step_number: int = Field(default=0, description="Current step in the episode")
    max_steps: int = Field(default=20, description="Maximum steps allowed")
    alerts: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of active alerts"
    )
    context_response: Optional[str] = Field(
        default=None,
        description="Response from the last context query",
    )
    action_feedback: str = Field(
        default="",
        description="Feedback from the last action taken",
    )
    classifications_made: Dict[str, str] = Field(
        default_factory=dict,
        description="Map of alert_id -> classification made so far",
    )
    actions_taken: List[str] = Field(
        default_factory=list,
        description="History of actions taken this episode",
    )
    available_actions: List[str] = Field(
        default_factory=list,
        description="List of valid action types for the current state",
    )
    score_so_far: float = Field(
        default=0.0,
        description="Running score for partial progress feedback",
    )


class SOCState(State):
    """Internal environment state for the SOC analyst environment."""

    task_id: str = Field(default="", description="Current task ID")
    alerts_ground_truth: Dict[str, str] = Field(
        default_factory=dict,
        description="Ground truth classifications for all alerts",
    )
    attack_chains: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Attack chain groupings (chain_id -> [alert_ids])",
    )
    queries_made: int = Field(
        default=0, description="Number of context queries made"
    )
    correct_classifications: int = Field(
        default=0, description="Number of correct classifications"
    )
    total_reward: float = Field(
        default=0.0, description="Cumulative reward this episode"
    )
