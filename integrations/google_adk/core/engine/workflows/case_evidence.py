from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter

from engine.domain import CaseEvidenceBatchResult, CaseEvidenceItem
from engine.parsing import parse_timestamp


def _clean_case_id(raw_id: Union[str, int]) -> str:
    """Extracts the numeric/terminal case identifier."""
    return str(raw_id).strip().split('/')[-1]


def _normalize_evidence_type(ev_type: str) -> str:
    """Normalizes evidence type string to API enum format."""
    t = ev_type.strip().upper()
    if t.startswith('EVIDENCE_TYPE_'):
        return t
    return f'EVIDENCE_TYPE_{t}'


class AttachCaseEvidenceWorkflow:
    """Batch attaches evidence items (detections, events, alerts) to a Google SecOps Case."""

    def __init__(self, adapter: Optional['GoogleSecOpsAdapter'] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: Union[str, int],
        evidence_items: List[Union[Dict[str, Any], str]],
        default_evidence_type: str = 'EVIDENCE_TYPE_DETECTION',
    ) -> CaseEvidenceBatchResult:
        """Attaches evidence items to the specified case."""
        if not case_id or not str(case_id).strip():
            raise ValueError('case_id must be a non-empty string or integer.')
        if not evidence_items:
            raise ValueError('evidence_items cannot be empty.')

        clean_case_id = _clean_case_id(case_id)
        requests: List[Dict[str, Any]] = []

        for item in evidence_items:
            if isinstance(item, str):
                requests.append({
                    'evidenceId': item.strip(),
                    'evidenceType': _normalize_evidence_type(default_evidence_type),
                })
            elif isinstance(item, dict):
                ev_id = str(item.get('evidenceId') or item.get('id') or '').strip()
                if not ev_id:
                    continue
                ev_type = item.get('evidenceType') or item.get('type') or default_evidence_type
                requests.append({
                    'evidenceId': ev_id,
                    'evidenceType': _normalize_evidence_type(ev_type),
                })

        if not requests:
            raise ValueError('No valid evidence items with non-empty evidenceId found.')

        raw = self.adapter.batch_attach_case_evidence(case_id=clean_case_id, evidence_requests=requests)

        items: List[CaseEvidenceItem] = []
        for ev in raw.get('caseEvidences', []):
            items.append(
                CaseEvidenceItem(
                    evidence_type=ev.get('evidenceType', ''),
                    evidence_id=ev.get('evidenceId', ''),
                    attach_time=parse_timestamp(ev.get('attachTime')),
                    attacher=ev.get('attacher'),
                    source_evidence_id=ev.get('sourceEvidenceId'),
                    source_evidence_type=ev.get('sourceEvidenceType'),
                    raw=ev,
                )
            )

        return CaseEvidenceBatchResult(
            case_id=clean_case_id,
            action="ATTACH",
            evidence_items=items,
            total_count=len(items),
            provenance={
                "workflow": "case.evidence.attach",
                "evidence_count": len(items),
            },
            raw=raw,
        )


class DetachCaseEvidenceWorkflow:
    """Batch detaches evidence items from a Google SecOps Case."""

    def __init__(self, adapter: Optional["GoogleSecOpsAdapter"] = None):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter

            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter

    def execute(
        self,
        case_id: Union[str, int],
        evidence_items: List[Union[Dict[str, Any], str]],
        default_evidence_type: str = "EVIDENCE_TYPE_DETECTION",
    ) -> CaseEvidenceBatchResult:
        """Detaches evidence items from the specified case."""
        if not case_id or not str(case_id).strip():
            raise ValueError("case_id must be a non-empty string or integer.")
        if not evidence_items:
            raise ValueError("evidence_items cannot be empty.")

        clean_case_id = _clean_case_id(case_id)
        requests: List[Dict[str, Any]] = []

        for item in evidence_items:
            if isinstance(item, str):
                requests.append({
                    "evidenceId": item.strip(),
                    "evidenceType": _normalize_evidence_type(default_evidence_type),
                })
            elif isinstance(item, dict):
                ev_id = str(item.get("evidenceId") or item.get("id") or "").strip()
                if not ev_id:
                    continue
                ev_type = item.get("evidenceType") or item.get("type") or default_evidence_type
                requests.append({
                    "evidenceId": ev_id,
                    "evidenceType": _normalize_evidence_type(ev_type),
                })

        if not requests:
            raise ValueError("No valid evidence items with non-empty evidenceId found.")

        raw = self.adapter.batch_detach_case_evidence(case_id=clean_case_id, evidence_requests=requests)

        items: List[CaseEvidenceItem] = [
            CaseEvidenceItem(
                evidence_type=r["evidenceType"],
                evidence_id=r["evidenceId"],
                raw=r,
            )
            for r in requests
        ]

        return CaseEvidenceBatchResult(
            case_id=clean_case_id,
            action="DETACH",
            evidence_items=items,
            total_count=len(items),
            provenance={
                "workflow": "case.evidence.detach",
                "evidence_count": len(items),
            },
            raw=raw,
        )
