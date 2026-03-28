"""
FastAPI application for the SOC Analyst Environment.

Custom stateful HTTP server that maintains environment state across
reset/step/state calls, as required by the OpenEnv hackathon infrastructure.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from models import SOCAction, SOCObservation, SOCState
from server.soc_environment import SOCEnvironment

# ============================================================================
# Request / Response models
# ============================================================================


class ResetRequest(BaseModel):
    seed: Optional[int] = Field(
        default=None, description="Random seed for reproducibility"
    )
    episode_id: Optional[str] = Field(default=None, description="Custom episode ID")
    task_id: Optional[str] = Field(default="soc_triage_easy", description="Task to run")


class StepRequest(BaseModel):
    action: Optional[Dict[str, Any]] = Field(
        default=None, description="Action dict (nested)"
    )
    # Also accept flat action fields for direct JSON
    action_type: Optional[str] = None
    alert_id: Optional[str] = None
    classification: Optional[str] = None
    query_type: Optional[str] = None
    alert_ids: Optional[list] = None
    report: Optional[str] = None
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: str = "healthy"


# ============================================================================
# Application
# ============================================================================

app = FastAPI(
    title="SOC Analyst Environment",
    description="Security Operations Center analyst simulation for AI agent training",
    version="1.0.0",
)

# Global environment instance (stateful across requests)
_env: Optional[SOCEnvironment] = None


def _get_env() -> SOCEnvironment:
    global _env
    if _env is None:
        raise HTTPException(
            status_code=400, detail="Environment not initialized. Call /reset first."
        )
    return _env


@app.get("/health", response_model=HealthResponse)
def health():
    """Health check endpoint."""
    return HealthResponse(status="healthy")


@app.post("/reset")
def reset(request: Optional[ResetRequest] = None):
    """Reset the environment and start a new episode."""
    global _env
    _env = SOCEnvironment()

    if request is None:
        request = ResetRequest()

    kwargs = {}
    if request.task_id:
        kwargs["task_id"] = request.task_id

    obs = _env.reset(
        seed=request.seed,
        episode_id=request.episode_id,
        **kwargs,
    )
    return obs.model_dump()


@app.post("/step")
def step(request: StepRequest):
    """Execute an action in the environment."""
    env = _get_env()

    # Build action from request - support both nested and flat formats
    action_data = {}
    if request.action:
        action_data = request.action
    else:
        # Flat format - collect non-None fields
        for field_name in [
            "action_type",
            "alert_id",
            "classification",
            "query_type",
            "alert_ids",
            "report",
            "reason",
        ]:
            val = getattr(request, field_name, None)
            if val is not None:
                action_data[field_name] = val

    if not action_data or "action_type" not in action_data:
        raise HTTPException(
            status_code=422,
            detail="Action must include 'action_type'. Send as flat JSON or nested under 'action' key.",
        )

    try:
        action = SOCAction(**action_data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid action: {str(e)}")

    obs = env.step(action)
    return obs.model_dump()


@app.get("/state")
def state():
    """Get the current environment state."""
    env = _get_env()
    return env.state.model_dump()


@app.get("/metadata")
def metadata():
    """Get environment metadata."""
    env_instance = SOCEnvironment()
    meta = env_instance.get_metadata()
    return meta.model_dump()


@app.get("/schema")
def schema():
    """Get action and observation schemas."""
    return {
        "action_schema": SOCAction.model_json_schema(),
        "observation_schema": SOCObservation.model_json_schema(),
        "state_schema": SOCState.model_json_schema(),
    }


@app.get("/tasks")
def list_tasks():
    """List available tasks."""
    from server.alerts_data import TASKS

    return {
        tid: {
            "task_id": t["task_id"],
            "description": t["description"],
            "difficulty": t["difficulty"],
            "max_steps": t["max_steps"],
            "available_actions": t["available_actions"],
        }
        for tid, t in TASKS.items()
    }


def main():
    import uvicorn

    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
