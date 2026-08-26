"""Response parsing for finding enrichment.

Local models in particular wrap their JSON in markdown fences or trail prose
after it, so extraction is forgiving and falls back to a synthesized payload
rather than failing the request.
"""

import json
import re
from typing import Any, Dict, List, Optional

from core.findings.enrichment.errors import EmptyProviderResponse

_FENCED_JSON = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_RAW_JSON = re.compile(r"\{.*\}", re.DOTALL)
_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

DEFAULT_TECHNIQUE_CONFIDENCE = 0.7


def extract_json_block(response: str) -> str:
    """Return the most likely JSON substring of ``response``.

    Prefers a ```json fenced block, then the first ``{...}`` span, then the
    whole response.
    """
    fenced = _FENCED_JSON.search(response)
    if fenced:
        return fenced.group(1)
    raw = _RAW_JSON.search(response)
    if raw:
        return raw.group(0)
    return response


def parse_enrichment(response: Optional[str], *, severity: str) -> Dict[str, Any]:
    """Parse a provider response into an enrichment payload.

    Raises:
        EmptyProviderResponse: the provider returned nothing to parse.
    """
    if not response:
        raise EmptyProviderResponse("LLM provider returned an empty response")

    try:
        return json.loads(extract_json_block(response))
    except json.JSONDecodeError:
        # Unparseable output still carries analyst value, so synthesize a
        # payload with the same shape the UI renders and park the raw text in
        # analysis_notes rather than 500-ing the request.
        return {
            "threat_summary": "AI analysis completed - see full analysis below",
            "threat_type": "Security Finding",
            "potential_impact": "Requires manual review",
            "risk_level": severity.title() if severity else "Medium",
            "recommended_actions": [
                "Review the detailed analysis",
                "Investigate related entities",
            ],
            "investigation_questions": [
                "What is the root cause?",
                "Are there related events?",
            ],
            "indicators": {},
            "related_techniques": [],
            "timeline_context": "Analysis in progress",
            "business_context": "Requires additional context",
            "confidence_score": 0.7,
            "analysis_notes": response[:1000],  # first 1000 chars as notes
            "raw_response": response,  # full response
        }


def normalize_technique_id(value: Any) -> Optional[str]:
    """Return a canonical ``T####`` / ``T####.###`` id, or None if none found."""
    if not isinstance(value, str):
        return None
    match = _TECHNIQUE_ID.search(value.strip())
    return match.group(0).upper() if match else None


def _confidence(value: Any, fallback: float) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return fallback
    if score < 0:
        return 0.0
    if score > 1:
        return 1.0
    return score


def _related_techniques_from_payload(payload: Any) -> List[Any]:
    if not isinstance(payload, dict):
        return []
    techniques = payload.get("related_techniques") or []
    return techniques if isinstance(techniques, list) else []


def _score_map_from_techniques(
    techniques: List[Any], fallback_confidence: float
) -> Dict[str, float]:
    predictions: Dict[str, float] = {}
    for item in techniques:
        if isinstance(item, str):
            tid = normalize_technique_id(item)
            if tid and tid not in predictions:
                predictions[tid] = fallback_confidence
            continue
        if not isinstance(item, dict):
            continue
        tid = normalize_technique_id(
            item.get("technique_id") or item.get("id") or item.get("technique")
        )
        if not tid or tid in predictions:
            continue
        predictions[tid] = _confidence(item.get("confidence"), fallback_confidence)
    return predictions


def mitre_predictions_from_enrichment(enrichment: Any) -> Dict[str, float]:
    """Map enrichment ``related_techniques`` onto ``mitre_predictions``.

    Prefers the already-parsed ``related_techniques`` list. If that is empty,
    re-parses ``raw_response`` so historical rows that only stored the model
    dump still yield technique ids. Rollup / Navigator / coverage tools read
    ``findings.mitre_predictions``, not the enrichment JSON.
    """
    if not isinstance(enrichment, dict) or not enrichment:
        return {}

    fallback = _confidence(
        enrichment.get("confidence_score"), DEFAULT_TECHNIQUE_CONFIDENCE
    )
    techniques = _related_techniques_from_payload(enrichment)
    predictions = _score_map_from_techniques(techniques, fallback)
    if predictions:
        return predictions

    raw = enrichment.get("raw_response")
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(extract_json_block(raw))
    except json.JSONDecodeError:
        return {}
    fallback = _confidence(
        parsed.get("confidence_score") if isinstance(parsed, dict) else None,
        fallback,
    )
    return _score_map_from_techniques(
        _related_techniques_from_payload(parsed), fallback
    )


def merge_mitre_predictions(
    existing: Any, extracted: Dict[str, float]
) -> Dict[str, float]:
    """Keep source-native scores; fill in techniques enrichment newly named.

    Ingest (CrowdStrike, Elastic, …) already writes high-confidence ids.
    Enrichment must not clobber those; it only adds missing keys.
    """
    merged: Dict[str, float] = {}
    if isinstance(existing, dict):
        for key, value in existing.items():
            tid = normalize_technique_id(key) or (
                key if isinstance(key, str) else None
            )
            if not tid:
                continue
            if isinstance(value, (int, float)):
                merged[tid] = _confidence(value, DEFAULT_TECHNIQUE_CONFIDENCE)
    elif isinstance(existing, list):
        merged.update(_score_map_from_techniques(existing, DEFAULT_TECHNIQUE_CONFIDENCE))
    for tid, score in extracted.items():
        if tid not in merged:
            merged[tid] = score
    return merged
