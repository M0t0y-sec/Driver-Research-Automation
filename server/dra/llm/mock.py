"""Deterministic mock LLM client.

The mock returns a structured payload per task. It is intentionally
simple: enough to drive the graph end-to-end without any external API.
When a real provider is wired in, swap this class at the composition
root (`dra.main` / `dra.llm.router.LLMRouter`).
"""

import json
import re
from typing import Any

from .base import LLMMessage, LLMResponse, LLMTask


def _safe_json(text: str) -> dict | None:
    """Extract the first JSON object from text."""
    text = text.strip()
    # Fenced
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Bare
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _extract_hypotheses_for_recon(observations: list[dict], attack_surface: list[dict]) -> list[dict]:
    """Generate plausible hypotheses from observations.

    Heuristic: for each observation whose category looks exploitable
    (memory_safety / input_validation / privilege), emit one hypothesis
    referencing the observation. The score breakdown is a
    rule-based estimate; LLM explanation is empty (mock).
    """
    candidates: list[dict] = []
    interesting = {
        "ioctl_code", "ioctl_dispatch", "device_exposure", "memory_copy",
        "input_validation", "privilege_check", "pointer_deref", "string",
    }
    for obs in observations:
        cat = obs.get("category", "")
        if cat not in interesting:
            continue
        # Reachability: any item in attack surface with low required priv
        reach = 0.0
        for as_ in attack_surface:
            if as_.get("reachability", {}).get("required_privilege", "") in {"", "unprivileged", "user"}:
                reach = max(reach, 0.7)
        candidates.append({
            "category": "memory_safety" if cat in {"memory_copy", "pointer_deref"} else (
                "input_validation" if cat in {"input_validation", "ioctl_code"} else
                "privilege" if cat == "privilege_check" else
                "logic"
            ),
            "location": obs.get("location"),
            "description": f"Potential issue in {cat} at {obs.get('location') or 'unknown'}; see observation {obs.get('id', '?')}.",
            "observation_ids": [obs.get("id")],
            # The hypothesis agent discards drafts without a falsifiable
            # prediction; the deterministic mock supplies a template one.
            "falsification": (
                f"Craft an input that reaches {obs.get('location') or 'the observed surface'} "
                f"and violates the assumption recorded in {obs.get('id', '?')}; if the "
                "target behaves safely under that input, the hypothesis is false."
            ),
            "score_breakdown": {
                "impact": 0.6,
                "confidence": 0.4,
                "reachability": reach or 0.5,
                "testability": 0.5,
                "rule_score": 0.5,
                "model_explanation": "(mock) heuristic from observation category",
                "uncertainty": "medium",
            },
            "requires_human_review": True,
        })
    # Add at least one hypothesis if none found
    if not candidates and observations:
        first = observations[0]
        candidates.append({
            "category": "logic",
            "location": first.get("location"),
            "description": f"Generic hypothesis from observation {first.get('id', '?')}; needs analyst review.",
            "observation_ids": [first.get("id")],
            "falsification": (
                f"Exercise the surface recorded in {first.get('id', '?')} and check "
                "whether the suspected unsafe behaviour is observable; if not, the "
                "hypothesis is false."
            ),
            "score_breakdown": {
                "impact": 0.3, "confidence": 0.3, "reachability": 0.4,
                "testability": 0.4, "rule_score": 0.3,
                "model_explanation": "(mock) fallback", "uncertainty": "high",
            },
            "requires_human_review": True,
        })
    return candidates


class MockLLMClient:
    """A deterministic mock that returns task-shaped JSON."""

    name = "mock"

    def complete(
        self,
        messages: list[LLMMessage],
        *,
        task: LLMTask,
        response_schema: dict | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        prompt = "\n".join(m.content for m in messages)
        structured: dict[str, Any] = {}

        if task == LLMTask.HYPOTHESIS_GEN:
            obs = self._extract_observations(prompt)
            as_ = self._extract_attack_surface(prompt)
            reverse_status = self._extract_reverse_status(prompt)
            if reverse_status in {"ok", "no_findings"}:
                # The reverse layer actually analysed the handler and the
                # mock has no dataflow reasoning to add. Returning zero
                # hypotheses is honest; the old template generator would
                # turn "an IOCTL exists" into a fake finding.
                structured = {
                    "hypotheses": [],
                    "reasoning": (
                        "(mock) The reverse agent analysed the handler "
                        f"(status={reverse_status}); the mock provider has no "
                        "dataflow reasoning, so it returns zero hypotheses "
                        "instead of fabricating one. Set DRA_LLM_PROVIDER="
                        "anthropic for real analysis."
                    ),
                }
            else:
                structured = {"hypotheses": _extract_hypotheses_for_recon(obs, as_)}
        elif task == LLMTask.STATIC_SUMMARY:
            structured = {
                "summary": "(mock) Reconnaissance summary generated from PE/imports/strings.",
                "highlights": [
                    "Driver entry IRP dispatch found",
                    "Multiple device names exported",
                    "Imports include kernel memory copy primitives",
                ],
            }
        elif task == LLMTask.QA_REVIEW:
            structured = {
                "decision": "pass",
                "reasons": [
                    "(mock) All cited observations have a non-empty source_tool and confidence.",
                    "(mock) Finding has at least one evidence_id referencing a static observation.",
                ],
                "counter_examples": [],
            }
        elif task == LLMTask.DETECTION_GAP:
            structured = {
                "weak_dimension": "behavior_correlation",
                "rationale": "(mock) Single-channel telemetry without cross-process correlation is the most likely gap.",
            }
        elif task == LLMTask.REPORT_GEN:
            structured = {
                "title": "Static Research Report",
                "executive_summary": "(mock) Driver exhibits an IOCTL dispatch surface with several user-reachable handlers; static analysis flagged a memory copy primitive near a likely input sink. No execution or live validation was performed in this phase.",
                "sections": [
                    {"heading": "Scope", "body": "Static PE/import/string analysis only."},
                    {"heading": "Findings", "body": "See candidate findings in the database."},
                    {"heading": "Limitations", "body": "No dynamic validation; no reverse engineering; no Lab execution."},
                ],
            }
        elif task == LLMTask.CODE_EXPLAIN:
            structured = {"explanation": "(mock) Function appears to dispatch IOCTL codes."}
        elif task == LLMTask.LABEL_EXTRACT:
            structured = {"labels": ["ioctl_dispatch", "user_reachable"]}
        elif task == LLMTask.JSON_REPAIR:
            structured = {"repaired": _safe_json(prompt) or {}}
        elif task == LLMTask.TOOL_OUTPUT_PARSE:
            structured = _safe_json(prompt) or {"raw": prompt[:200]}
        else:
            structured = {"echo": prompt[:200]}

        return LLMResponse(
            content=json.dumps(structured, ensure_ascii=False),
            structured=structured,
            model=self.name,
            temperature=temperature if temperature is not None else 0.0,
        )

    @staticmethod
    def _extract_observations(prompt: str) -> list[dict]:
        # Best-effort parse of the pipe-delimited observation lines emitted by
        # the hypothesis agent:
        #   - id: OBS-... | category: ioctl_code | location: IOCTL 0x... | ...
        items: list[dict] = []
        for line in prompt.splitlines():
            m = re.search(
                r"id:\s*(OBS-[A-Z0-9-]+)\s*\|\s*category:\s*([a-z_]+)"
                r"(?:\s*\|\s*location:\s*([^|]*))?",
                line,
            )
            if not m:
                continue
            location = (m.group(3) or "").strip() or None
            items.append({"id": m.group(1), "category": m.group(2), "location": location})
        return items

    @staticmethod
    def _extract_reverse_status(prompt: str) -> str | None:
        match = re.search(r"REVERSE ANALYSIS STATUS:\s*([a-z_]+)", prompt)
        return match.group(1) if match else None

    @staticmethod
    def _extract_attack_surface(prompt: str) -> list[dict]:
        items: list[dict] = []
        for m in re.finditer(
            r"name:\s*([A-Za-z0-9_]+).*?reachability:\s*\{([^}]*)\}",
            prompt,
            re.S,
        ):
            block = m.group(2)
            req = re.search(r"required_privilege:\s*(\S+)", block)
            items.append(
                {
                    "name": m.group(1),
                    "reachability": {
                        "required_privilege": req.group(1) if req else "",
                    },
                }
            )
        return items
