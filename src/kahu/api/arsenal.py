"""Arsenal API — unlocked mode tooling and AI-driven offensive recommendations."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from kahu.clients.ollama import OllamaClient
from kahu.services.arsenal.catalog import (
    build_methodology_context,
    build_tool_context,
    get_catalog,
    get_categories,
    get_tool,
    get_tools_by_category,
    get_tools_for_phase,
)
from kahu.services.arsenal.mode import is_unlocked, lock, status, unlock

router = APIRouter()


ARSENAL_SYSTEM = (
    "You are Kahu in unlocked mode — an expert penetration tester"
    " and red team operator.\n"
    "You have deep knowledge of every tool in the Kali Linux arsenal"
    " and follow PTES methodology.\n"
    "\n"
    "Your job: given a target, objective, and access level,"
    " recommend the exact tools and commands to use.\n"
    "\n"
    "Rules:\n"
    "- Be specific. Give exact commands with real flags,"
    " not vague suggestions.\n"
    "- Substitute {target} with the actual target provided.\n"
    "- For UNAUTHENTICATED testing: start with passive recon,"
    " then active scanning, then exploitation.\n"
    "- For AUTHENTICATED testing: start with AD enumeration,"
    " then privilege escalation, then lateral movement.\n"
    "- For FULL testing: cover both phases in logical order.\n"
    "- Warn about noisy techniques that may trigger IDS/IPS.\n"
    "- Note which techniques require specific authorization scope.\n"
    "- If multiple approaches exist, recommend the most"
    " reliable one first.\n"
    "- Always include how to verify success after each step.\n"
    "- Include credential handling: where to store found creds,"
    " how to reuse them.\n"
    "- For AD environments, always check for Kerberoasting,"
    " AS-REP roasting, and delegation abuse.\n"
    "- Note when a tool needs root/admin/SYSTEM privileges.\n"
)


# ── Mode Control ──────────────────────────────────────────


class ModeToggle(BaseModel):
    analyst: str = Field(..., min_length=1, max_length=255)


class ModeStatus(BaseModel):
    mode: str
    unlocked_by: str
    unlocked_at: str | None


@router.get("/status", response_model=ModeStatus)
async def arsenal_status():
    """Check current arsenal mode."""
    return status()


@router.post("/unlock", response_model=ModeStatus)
async def arsenal_unlock(body: ModeToggle):
    """Switch to unlocked mode — enables offensive tooling."""
    return unlock(body.analyst)


@router.post("/lock", response_model=ModeStatus)
async def arsenal_lock(body: ModeToggle):
    """Return to guardian mode — disables offensive tooling."""
    return lock(body.analyst)


# ── Tool Catalog ──────────────────────────────────────────


@router.get("/tools")
async def list_tools(category: str = "", phase: str = ""):
    """List available tools, optionally filtered by category or pentest phase."""
    _require_unlocked()
    if category:
        tools = get_tools_by_category(category)
    elif phase:
        tools = get_tools_for_phase(phase)
    else:
        tools = get_catalog()
    return {"tools": tools, "categories": get_categories(), "count": len(tools)}


@router.get("/tools/{tool_name}")
async def tool_detail(tool_name: str):
    """Get detailed info for a specific tool."""
    _require_unlocked()
    tool = get_tool(tool_name)
    if not tool:
        raise HTTPException(404, f"Tool '{tool_name}' not found in catalog")
    return tool


# ── AI Attack Planner ─────────────────────────────────────


class AttackPlanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500)
    objective: str = Field(..., min_length=1, max_length=2000)
    scope: str = Field(default="full", description="full | external | internal | web | wireless")
    phase: str = Field(default="both", description="unauthenticated | authenticated | both")
    credentials: str = Field(
        default="",
        max_length=2000,
        description="Known credentials, e.g. 'user:pass, domain\\admin:P@ss'",
    )
    constraints: str = Field(
        default="", max_length=1000, description="e.g. 'no DoS, stealth only, business hours only'"
    )


class AttackPlanResponse(BaseModel):
    plan: str
    tools_referenced: list[str]
    phase: str
    degraded: bool = False


@router.post("/plan", response_model=AttackPlanResponse)
async def generate_attack_plan(body: AttackPlanRequest) -> AttackPlanResponse:
    """Generate an AI-powered attack plan for a target."""
    _require_unlocked()

    tool_context = build_tool_context()
    methodology = build_methodology_context(body.phase)

    cred_section = ""
    if body.credentials:
        cred_section = f"""
Known Credentials:
{body.credentials}
Use these for authenticated testing phases. Try pass-the-hash, Kerberos ticket attacks,
and lateral movement with these credentials."""

    phase_hint = ""
    if body.phase == "both":
        phase_hint = (
            "Start with unauthenticated/external testing,"
            " then move to authenticated/internal."
        )
    elif body.phase == "unauthenticated":
        phase_hint = (
            "Focus on what can be discovered WITHOUT credentials."
        )
    elif body.phase == "authenticated":
        phase_hint = (
            "Focus on post-compromise activities"
            " — privilege escalation, lateral movement,"
            " persistence."
        )

    constraints_line = (
        f"Constraints: {body.constraints}" if body.constraints else ""
    )

    prompt = f"""Target: {body.target}
Objective: {body.objective}
Scope: {body.scope}
Phase: {body.phase}
{constraints_line}
{cred_section}

Generate a step-by-step attack plan following PTES methodology.
For each step:
1. Name the tool and exact command
2. Explain what information you expect to gather
3. How to interpret the results
4. What to do next based on findings
5. Note if the step requires authentication or elevated privileges

{phase_hint}

Be thorough but realistic. This is an authorized penetration test."""

    system = ARSENAL_SYSTEM + methodology + "\n\n# Available Tools\n" + tool_context

    ollama = OllamaClient()
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        response = await ollama.generate(prompt=prompt, system=system)

        # Extract tool names referenced in the response
        catalog = get_catalog()
        tools_used = [t["name"] for t in catalog if t["name"].lower() in response.lower()]

        return AttackPlanResponse(
            plan=response.strip(),
            tools_referenced=tools_used,
            phase=body.phase,
        )
    except Exception:
        return AttackPlanResponse(
            plan="AI engine is offline. Use the tool catalog to manually plan your assessment.",
            tools_referenced=[],
            phase=body.phase,
            degraded=True,
        )


# ── Tool Command Builder ─────────────────────────────────


class CommandRequest(BaseModel):
    tool: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    objective: str = Field(default="", max_length=1000)
    credentials: str = Field(
        default="", max_length=500, description="user:pass or domain/user:pass"
    )


class CommandResponse(BaseModel):
    tool: str
    commands: list[str]
    explanation: str
    degraded: bool = False


@router.post("/command", response_model=CommandResponse)
async def build_command(body: CommandRequest) -> CommandResponse:
    """AI-generate the optimal command for a specific tool and target."""
    _require_unlocked()

    tool = get_tool(body.tool)
    if not tool:
        raise HTTPException(404, f"Tool '{body.tool}' not found")

    cred_hint = (
        "Include both unauthenticated and authenticated"
        " variants if the tool supports it."
        if body.credentials
        else "Focus on unauthenticated usage."
    )

    prompt = f"""Tool: {tool["name"]}
Description: {tool["description"]}
Target: {body.target}
{f"Objective: {body.objective}" if body.objective else ""}
{f"Credentials: {body.credentials}" if body.credentials else "No credentials (unauthenticated)"}

Example commands:
{chr(10).join(tool["examples"])}

{f"Available flags: {tool['flags']}" if tool.get("flags") else ""}

Generate the best command(s) for this specific target and objective.
{cred_hint}
Return each command on its own line.
Then explain what each does and what to look for in the output."""

    ollama = OllamaClient()
    try:
        if not await ollama.health():
            raise RuntimeError("Ollama offline")
        response = await ollama.generate(
            prompt=prompt, system=ARSENAL_SYSTEM + build_tool_context()
        )

        # Try to extract commands (lines starting with tool name or common prefixes)
        lines = response.strip().split("\n")
        commands = []
        explanation_lines = []
        for line in lines:
            stripped = line.strip().lstrip("$").lstrip(">").strip()
            if stripped.startswith(tool["name"]) or stripped.startswith(f"sudo {tool['name']}"):
                commands.append(stripped)
            elif stripped.startswith("`") and stripped.endswith("`"):
                commands.append(stripped.strip("`"))
            else:
                explanation_lines.append(line)

        # Fallback: use template examples with target substituted
        if not commands:
            commands = [ex.replace("{target}", body.target) for ex in tool["examples"][:3]]

        return CommandResponse(
            tool=tool["name"],
            commands=commands,
            explanation="\n".join(explanation_lines).strip() or response.strip(),
        )
    except Exception:
        commands = [ex.replace("{target}", body.target) for ex in tool["examples"][:3]]
        return CommandResponse(
            tool=tool["name"],
            commands=commands,
            explanation=f"AI offline. Showing template commands for {tool['name']}.",
            degraded=True,
        )


def _require_unlocked():
    if not is_unlocked():
        raise HTTPException(403, "Arsenal is locked. Switch to unlocked mode first.")
