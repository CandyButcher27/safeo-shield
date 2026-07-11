from pydantic import BaseModel
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime


# ─── Legacy WAF models (kept for backward-compat with Odoo controller) ────────

class WAFInputRequest(BaseModel):
    input_text: str
    user_id: Optional[str] = "anonymous"
    module: Optional[str] = "generic"
    context: Optional[Dict[str, Any]] = {}


class AgentResult(BaseModel):
    agent_name: str
    status: str
    decision: str
    confidence: float
    detected_patterns: List[str]


class WAFResponse(BaseModel):
    risk_score: float
    decision: str
    explanation: str
    detected_patterns: List[str]
    agents: List[AgentResult]
    sanitized_text: Optional[str] = None
    request_id: str
    llm_used: Optional[bool] = None
    decision_cache_hit: Optional[bool] = None
    engine_note: Optional[str] = None
    # ERP enrichment fields
    affected_module: Optional[str] = None
    erp_impact: Optional[str] = None


class WAFOutputRequest(BaseModel):
    output_text: str
    user_id: Optional[str] = "anonymous"
    module: Optional[str] = "generic"


class BehaviorRequest(BaseModel):
    user_id: str
    action: str
    module: Optional[str] = "generic"
    timestamp: Optional[datetime] = None


class BehaviorResponse(BaseModel):
    user_id: str
    risk_score: float
    anomaly_detected: bool
    explanation: str
    action_count: int
    baseline_avg: float
    behavioural_risk_score: float = 0.0


class SimulateRequest(BaseModel):
    attack_types: Optional[List[str]] = None


class SimulationResult(BaseModel):
    attack_type: str
    payload: str
    detected: bool
    risk_score: float
    decision: str
    explanation: str


class SimulateResponse(BaseModel):
    total_attacks: int
    detected_count: int
    detection_rate: float
    results: List[SimulationResult]


class FeedbackRequest(BaseModel):
    request_id: str
    correct_decision: str
    notes: Optional[str] = None


class MetricsResponse(BaseModel):
    total_requests: int
    blocked_count: int
    warned_count: int
    allowed_count: int
    block_rate: float
    avg_risk_score: float
    threats_by_module: Dict[str, int]
    risk_distribution: Dict[str, int]
    recent_attacks: List[Dict[str, Any]]
    llm_calls_total: int = 0
    llm_calls_skipped: int = 0
    decision_cache_hits: int = 0
    # ERP enrichment
    erp_module_breakdown: Optional[Dict[str, int]] = None
    recent_decisions: Optional[List[Dict[str, Any]]] = None
    network_risk_events: int = 0


# ─── ERP-native request / response models ─────────────────────────────────────

class TransactionRiskRequest(BaseModel):
    """A financial or operational ERP transaction submitted for risk analysis."""
    transaction_id: Optional[str] = None
    amount: Optional[float] = None
    transaction_type: Optional[str] = "payment"   # payment | approval | procurement | invoice
    description: str                               # free-text field that gets scanned
    user_id: Optional[str] = "anonymous"
    department: Optional[str] = None
    erp_module: Optional[str] = "Finance"          # Finance | CRM | HR | Procurement
    network_context: Optional[str] = "safe"        # safe | risky


class EmployeeActivityRequest(BaseModel):
    """An employee action submitted for behavioral risk assessment."""
    employee_id: str
    role: Optional[str] = "user"
    action: str                                    # action description / payload
    department: Optional[str] = None
    erp_module: Optional[str] = "HR"
    network_context: Optional[str] = "safe"


class CRMLeadRequest(BaseModel):
    lead_id: Optional[str] = None
    name: str
    message: str
    source: Optional[str] = "web"
    user_id: Optional[str] = "crm_user"
    network_context: Optional[str] = "safe"


class FinancialActionRequest(BaseModel):
    action_id: Optional[str] = None
    action_type: Optional[str] = "payment"          # payment | approval | reimbursement
    amount: Optional[float] = None
    notes: Optional[str] = ""
    approver_id: Optional[str] = "finance_user"
    network_context: Optional[str] = "safe"


class ERPDecisionResponse(BaseModel):
    """Structured ERP-context risk decision returned to ERP modules."""
    request_id: str
    risk_score: int                                # 0–100 (integer for UX clarity)
    risk_score_raw: float                          # 0.0–1.0 raw float
    decision: Literal["ALLOW", "WARN", "BLOCK"]
    reason: str
    affected_module: str                           # CRM | Finance | HR | Procurement | Auth
    user_id: str
    network_signal: Literal["safe", "risky"] = "safe"
    erp_impact: str                                # "transaction_approved" | "flagged_for_review" | "transaction_blocked"
    detected_patterns: List[str] = []
    timestamp: Optional[str] = None


class NetworkSignalResponse(BaseModel):
    signal: Literal["safe", "risky"]
    reason: str
    risk_boost: float                              # additive boost applied to risk scores
