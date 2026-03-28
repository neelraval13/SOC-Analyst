"""
SOC Analyst Environment - Core environment logic.

Implements the OpenEnv Environment interface for a Security Operations Center
analyst simulation with 3 tasks: triage, investigation, and multi-alert correlation.
"""

import uuid
from typing import Any, Dict, List, Optional

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata

from models import SOCAction, SOCObservation, SOCState
from server.alerts_data import TASKS, get_context_response
from server.graders import (
    compute_step_reward,
    grade_task1_triage,
    grade_task2_investigation,
    grade_task3_correlation,
)


class SOCEnvironment(Environment[SOCAction, SOCObservation, SOCState]):
    """
    Security Operations Center Analyst Environment.

    Simulates real-world SOC analyst workflows:
    - Task 1 (Easy): Alert triage - classify 5 alerts
    - Task 2 (Medium): Incident investigation - query context, diagnose, respond
    - Task 3 (Hard): Multi-alert correlation - identify attack campaign
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        super().__init__()
        self._episode_id: Optional[str] = None
        self._step_count: int = 0
        self._task_id: str = ""
        self._task_config: Dict[str, Any] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._ground_truth: Dict[str, str] = {}
        self._attack_chains: Dict[str, List[str]] = {}
        self._classifications: Dict[str, str] = {}
        self._actions_taken: List[str] = []
        self._containment_actions: List[str] = []
        self._escalation_actions: List[str] = []
        self._dismissal_actions: List[str] = []
        self._correlated_chains: List[List[str]] = []
        self._queries_made: int = 0
        self._total_reward: float = 0.0
        self._done: bool = False
        self._last_feedback: str = ""
        self._last_context: Optional[str] = None
        self._report_submitted: bool = False
        self._report_text: str = ""
        self._max_steps: int = 20

    def get_metadata(self) -> EnvironmentMetadata:
        return EnvironmentMetadata(
            name="soc_analyst_env",
            description=(
                "Security Operations Center Analyst Environment. "
                "Simulates real-world SOC workflows: alert triage, "
                "incident investigation, and multi-alert correlation."
            ),
        )

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """Reset the environment for a new episode.

        kwargs:
            task_id: str - which task to load
        """
        self._episode_id = episode_id or str(uuid.uuid4())
        self._step_count = 0

        # Determine task
        task_id = kwargs.get("task_id", "soc_triage_easy")
        if task_id not in TASKS:
            task_id = "soc_triage_easy"

        self._task_id = task_id
        self._task_config = TASKS[task_id]
        self._max_steps = self._task_config["max_steps"]

        # Generate alerts
        generator = self._task_config["generator"]
        effective_seed = seed if seed is not None else 42
        self._alerts = generator(seed=effective_seed)

        # Store ground truth (hidden from agent)
        self._ground_truth = {}
        self._attack_chains = {}
        for alert in self._alerts:
            self._ground_truth[alert["alert_id"]] = alert.get("ground_truth", "unknown")
            chain_id = alert.get("attack_chain_id")
            if chain_id:
                if chain_id not in self._attack_chains:
                    self._attack_chains[chain_id] = []
                self._attack_chains[chain_id].append(alert["alert_id"])

        # Reset tracking
        self._classifications = {}
        self._actions_taken = []
        self._containment_actions = []
        self._escalation_actions = []
        self._dismissal_actions = []
        self._correlated_chains = []
        self._queries_made = 0
        self._total_reward = 0.0
        self._done = False
        self._last_feedback = (
            "Environment reset. Review the alerts and begin your analysis."
        )
        self._last_context = None
        self._report_submitted = False
        self._report_text = ""

        return self._build_observation()

    def step(
        self,
        action: SOCAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """Process an agent action and return the new observation."""
        if self._done:
            return self._build_observation()

        self._step_count += 1
        self._last_context = None
        reward = 0.0

        action_type = action.action_type.lower().strip()

        if action_type == "classify":
            reward = self._handle_classify(action)
        elif action_type == "query_context":
            reward = self._handle_query(action)
        elif action_type == "escalate":
            reward = self._handle_escalate(action)
        elif action_type == "contain":
            reward = self._handle_contain(action)
        elif action_type == "dismiss":
            reward = self._handle_dismiss(action)
        elif action_type == "correlate":
            reward = self._handle_correlate(action)
        elif action_type == "submit_report":
            reward = self._handle_report(action)
        else:
            self._last_feedback = (
                f"Unknown action type '{action_type}'. "
                f"Valid actions: {', '.join(self._task_config['available_actions'])}"
            )
            reward = -0.02

        # Record action
        action_record = f"{action_type}"
        if action.alert_id:
            action_record += f":{action.alert_id}"
        if action.classification:
            action_record += f"={action.classification}"
        if action.query_type:
            action_record += f"?{action.query_type}"
        self._actions_taken.append(action_record)

        self._total_reward += reward

        # Check completion conditions
        self._check_done()

        return self._build_observation(step_reward=reward)

    @property
    def state(self) -> SOCState:
        """Return the current internal state."""
        return SOCState(
            episode_id=self._episode_id,
            step_count=self._step_count,
            task_id=self._task_id,
            alerts_ground_truth=self._ground_truth,
            attack_chains=self._attack_chains,
            queries_made=self._queries_made,
            correct_classifications=sum(
                1
                for aid, cls in self._classifications.items()
                if cls == self._ground_truth.get(aid)
            ),
            total_reward=self._total_reward,
        )

    def close(self) -> None:
        """Clean up resources."""
        pass

    # ========================================================================
    # Action handlers
    # ========================================================================

    def _handle_classify(self, action: SOCAction) -> float:
        if not action.alert_id:
            self._last_feedback = "Error: classify action requires alert_id."
            return -0.01

        if not action.classification:
            self._last_feedback = "Error: classify action requires classification (true_positive, false_positive, needs_investigation)."
            return -0.01

        valid_classes = ["true_positive", "false_positive", "needs_investigation"]
        if action.classification not in valid_classes:
            self._last_feedback = f"Error: invalid classification '{action.classification}'. Must be one of: {valid_classes}"
            return -0.01

        alert = self._find_alert(action.alert_id)
        if not alert:
            self._last_feedback = f"Error: alert '{action.alert_id}' not found."
            return -0.01

        self._classifications[action.alert_id] = action.classification
        gt = self._ground_truth.get(action.alert_id, "unknown")

        reward = compute_step_reward(
            action_type="classify",
            alert=alert,
            classification=action.classification,
            ground_truth=gt,
            severity=alert.get("severity_hint", "medium"),
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = (
            f"Alert {action.alert_id} classified as '{action.classification}'. "
            f"Classification recorded."
        )
        return reward

    def _handle_query(self, action: SOCAction) -> float:
        if not action.alert_id:
            self._last_feedback = "Error: query_context action requires alert_id."
            return -0.01

        valid_queries = ["user_profile", "network_logs", "threat_intel", "asset_info"]
        if not action.query_type or action.query_type not in valid_queries:
            self._last_feedback = f"Error: query_type must be one of: {valid_queries}"
            return -0.01

        alert = self._find_alert(action.alert_id)
        if not alert:
            self._last_feedback = f"Error: alert '{action.alert_id}' not found."
            return -0.01

        self._queries_made += 1

        context = get_context_response(action.query_type, alert)
        self._last_context = context

        is_useful = False
        gt = self._ground_truth.get(action.alert_id, "unknown")
        if gt == "true_positive":
            is_useful = True
        elif action.query_type == "threat_intel":
            is_useful = True

        reward = compute_step_reward(
            action_type="query_context",
            alert=alert,
            classification=None,
            ground_truth=gt,
            severity=alert.get("severity_hint", "medium"),
            is_useful_query=is_useful,
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = f"Context query '{action.query_type}' completed for alert {action.alert_id}."
        return reward

    def _handle_escalate(self, action: SOCAction) -> float:
        if not action.alert_id:
            self._last_feedback = "Error: escalate action requires alert_id."
            return -0.01

        alert = self._find_alert(action.alert_id)
        if not alert:
            self._last_feedback = f"Error: alert '{action.alert_id}' not found."
            return -0.01

        self._escalation_actions.append(f"escalate:{action.alert_id}")
        gt = self._ground_truth.get(action.alert_id, "unknown")

        reward = compute_step_reward(
            action_type="escalate",
            alert=alert,
            classification=None,
            ground_truth=gt,
            severity=alert.get("severity_hint", "medium"),
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = (
            f"Alert {action.alert_id} escalated to Incident Response team."
        )
        return reward

    def _handle_contain(self, action: SOCAction) -> float:
        if not action.alert_id:
            self._last_feedback = "Error: contain action requires alert_id."
            return -0.01

        alert = self._find_alert(action.alert_id)
        if not alert:
            self._last_feedback = f"Error: alert '{action.alert_id}' not found."
            return -0.01

        self._containment_actions.append(f"contain:{action.alert_id}")
        gt = self._ground_truth.get(action.alert_id, "unknown")

        reward = compute_step_reward(
            action_type="contain",
            alert=alert,
            classification=None,
            ground_truth=gt,
            severity=alert.get("severity_hint", "medium"),
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = (
            f"Containment action executed for alert {action.alert_id}. "
            f"Source host {alert.get('source_ip', 'unknown')} isolated from network."
        )
        return reward

    def _handle_dismiss(self, action: SOCAction) -> float:
        if not action.alert_id:
            self._last_feedback = "Error: dismiss action requires alert_id."
            return -0.01

        alert = self._find_alert(action.alert_id)
        if not alert:
            self._last_feedback = f"Error: alert '{action.alert_id}' not found."
            return -0.01

        self._dismissal_actions.append(f"dismiss:{action.alert_id}")
        gt = self._ground_truth.get(action.alert_id, "unknown")

        reward = compute_step_reward(
            action_type="dismiss",
            alert=alert,
            classification=None,
            ground_truth=gt,
            severity=alert.get("severity_hint", "medium"),
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = f"Alert {action.alert_id} dismissed as benign."
        return reward

    def _handle_correlate(self, action: SOCAction) -> float:
        if not action.alert_ids or len(action.alert_ids) < 2:
            self._last_feedback = (
                "Error: correlate action requires alert_ids with at least 2 alert IDs."
            )
            return -0.01

        valid_ids = [a["alert_id"] for a in self._alerts]
        for aid in action.alert_ids:
            if aid not in valid_ids:
                self._last_feedback = f"Error: alert '{aid}' not found."
                return -0.01

        self._correlated_chains.append(list(action.alert_ids))

        actual_chain_alerts = []
        for chain_alerts in self._attack_chains.values():
            actual_chain_alerts.extend(chain_alerts)

        correlated_set = set(action.alert_ids)
        actual_set = set(actual_chain_alerts)

        if actual_set:
            overlap = len(correlated_set & actual_set)
            precision = overlap / len(correlated_set) if correlated_set else 0
            recall = overlap / len(actual_set) if actual_set else 0
        else:
            precision = 0
            recall = 0

        reward = compute_step_reward(
            action_type="correlate",
            alert=None,
            classification=None,
            ground_truth=None,
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        if precision > 0.5 and recall > 0.3:
            reward += 0.15
        elif precision > 0.3:
            reward += 0.05

        self._last_feedback = (
            f"Correlation recorded: {len(action.alert_ids)} alerts grouped as related incident. "
            f"IDs: {', '.join(action.alert_ids)}"
        )
        return reward

    def _handle_report(self, action: SOCAction) -> float:
        if not action.report:
            self._last_feedback = "Error: submit_report action requires report text."
            return -0.01

        self._report_submitted = True
        self._report_text = action.report

        reward = compute_step_reward(
            action_type="submit_report",
            alert=None,
            classification=None,
            ground_truth=None,
            step_count=self._step_count,
            max_steps=self._max_steps,
        )

        self._last_feedback = "Incident report submitted successfully."
        return reward

    # ========================================================================
    # Helpers
    # ========================================================================

    def _find_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        for alert in self._alerts:
            if alert["alert_id"] == alert_id:
                return alert
        return None

    def _sanitize_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Remove hidden fields before showing to agent."""
        return {
            k: v
            for k, v in alert.items()
            if k
            not in (
                "ground_truth",
                "attack_chain_id",
                "_correct_diagnosis",
                "_correct_action",
            )
        }

    def _check_done(self):
        """Check if the episode should end."""
        if self._step_count >= self._max_steps:
            self._done = True
            self._last_feedback += " Maximum steps reached. Episode ending."
            return

        if self._task_id == "soc_triage_easy":
            if len(self._classifications) >= len(self._alerts):
                self._done = True
                self._last_feedback += " All alerts classified. Episode complete."

        elif self._task_id == "soc_investigate_medium":
            all_classified = len(self._classifications) >= len(self._alerts)
            has_response = (
                len(self._containment_actions)
                + len(self._escalation_actions)
                + len(self._dismissal_actions)
            ) > 0
            if all_classified and has_response:
                self._done = True
                self._last_feedback += " Investigation complete. Episode ending."

        elif self._task_id == "soc_correlate_hard":
            if self._report_submitted:
                self._done = True
                self._last_feedback += " Report submitted. Episode complete."

    def _compute_final_score(self) -> float:
        """Compute the final grader score for the episode."""
        if self._task_id == "soc_triage_easy":
            return grade_task1_triage(
                classifications=self._classifications,
                ground_truth=self._ground_truth,
                alerts=self._alerts,
                step_count=self._step_count,
                max_steps=self._max_steps,
            )
        elif self._task_id == "soc_investigate_medium":
            return grade_task2_investigation(
                classifications=self._classifications,
                ground_truth=self._ground_truth,
                alerts=self._alerts,
                actions_taken=self._actions_taken,
                queries_made=self._queries_made,
                containment_actions=self._containment_actions,
                escalation_actions=self._escalation_actions,
                dismissal_actions=self._dismissal_actions,
                step_count=self._step_count,
                max_steps=self._max_steps,
            )
        elif self._task_id == "soc_correlate_hard":
            actual_chain_alerts = []
            for chain_alerts in self._attack_chains.values():
                actual_chain_alerts.extend(chain_alerts)
            return grade_task3_correlation(
                classifications=self._classifications,
                ground_truth=self._ground_truth,
                alerts=self._alerts,
                correlated_chains=self._correlated_chains,
                actual_chain_alerts=actual_chain_alerts,
                report_submitted=self._report_submitted,
                report_text=self._report_text,
                actions_taken=self._actions_taken,
                containment_actions=self._containment_actions,
                step_count=self._step_count,
                max_steps=self._max_steps,
            )
        return 0.0

    def _build_observation(self, step_reward: float = 0.0) -> SOCObservation:
        """Build the observation to return to the agent."""
        final_reward = None
        if self._done:
            final_reward = self._compute_final_score()

        sanitized_alerts = [self._sanitize_alert(a) for a in self._alerts]

        return SOCObservation(
            done=self._done,
            reward=final_reward if self._done else step_reward,
            metadata={
                "episode_id": self._episode_id,
                "final_score": final_reward if self._done else None,
                "cumulative_reward": self._total_reward,
            },
            task_id=self._task_id,
            task_description=self._task_config.get("description", ""),
            step_number=self._step_count,
            max_steps=self._max_steps,
            alerts=sanitized_alerts,
            context_response=self._last_context,
            action_feedback=self._last_feedback,
            classifications_made=dict(self._classifications),
            actions_taken=list(self._actions_taken),
            available_actions=self._task_config.get("available_actions", []),
            score_so_far=self._total_reward,
        )
