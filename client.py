"""
SOC Analyst Environment Client.

Provides SOCEnv client for connecting to a running SOC Analyst environment.
"""

from openenv.core.env_client import EnvClient

from models import SOCAction, SOCObservation, SOCState


class SOCEnv(EnvClient[SOCAction, SOCObservation, SOCState]):
    """Client for the SOC Analyst Environment."""

    def _parse_observation(self, data: dict) -> SOCObservation:
        return SOCObservation(**data)

    def _serialize_action(self, action: SOCAction) -> dict:
        return action.model_dump(exclude_none=True)
