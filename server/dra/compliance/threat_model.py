"""Threat model definitions and reachability helpers.

The threat model is the set of attack-actor profiles the platform
considers when scoring hypotheses and gating detections. See
integration plan section 1A.2.
"""

ATTACK_ACTORS: list[str] = [
    "unprivileged_local_user",
    "sandboxed_process",
    "service_account",
    "local_administrator",
    "remote_attacker",
    "physical",
    "unknown",
]


def attack_actor(name: str) -> str:
    name = (name or "").strip().lower()
    if name not in ATTACK_ACTORS:
        return "unknown"
    return name


# Reachability hints used by the static analyst when generating attack
# surface items. These are conservative defaults: an item is considered
# user-reachable unless we have evidence otherwise.
USER_REACHABLE = {
    "unprivileged_local_user",
    "sandboxed_process",
    "service_account",
    "local_administrator",
}
