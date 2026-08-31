// ============================================================================
// DRA Domain Types — aligned with `server/dra/models/*.py`
// See: "DRA — Driver Research Automation 整合方案 v2.md" §7 + §8.
// ============================================================================

// ---------- Common enums (mirror server/dra/models/common.py) ----------

export type Confidence = 'high' | 'medium' | 'low'
export type Status =
  | 'idle'
  | 'running'
  | 'paused'
  | 'waiting_approval'
  | 'failed'
  | 'completed'
  | 'cancelled'

export type EvidenceStrength = 'E0' | 'E1' | 'E2' | 'E3' | 'E4' | 'E5' | 'E6' | 'E7'

export type FailureClass =
  | 'env_failure'
  | 'tool_failure'
  | 'timeout'
  | 'policy_denied'
  | 'invalid_input'
  | 'target_error'
  | 'experiment_failure'
  | 'telemetry_invisible'
  | 'model_error'
  | 'evidence_insufficient'

export type RiskLevel = 'low' | 'medium' | 'high' | 'extreme'

export type ToolRunStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'timeout'
  | 'cancelled'
  | 'needs_approval'
  | 'blocked_by_policy'

export type HypothesisStatus =
  | 'proposed'
  | 'queued'
  | 'selected'
  | 'planned'
  | 'validating'
  | 'confirmed'
  | 'rejected'
  | 'inconclusive'
  | 'needs_human'
  | 'archived'

export type ExperimentStatus =
  | 'draft'
  | 'needs_approval'
  | 'approved'
  | 'scheduled'
  | 'preparing'
  | 'running'
  | 'collecting'
  | 'triaging'
  | 'completed'
  | 'cancelled'
  | 'failed_environment'
  | 'failed_target'
  | 'failed_telemetry'
  | 'inconclusive'
  | 'archived'

export type FindingStatus =
  | 'candidate'
  | 'evidence_review'
  | 'qa_pass'
  | 'human_approved'
  | 'confirmed'
  | 'false_positive'
  | 'needs_human'
  | 'archived'
  | 'disclosed'

export type QADecision = 'pass' | 'retry' | 'reject' | 'inconclusive'

export type DetectionVerdict =
  | 'detected'
  | 'not_observed'
  | 'inconclusive'
  | 'blocked'

export type DetectionStage = 'none' | 'realtime' | 'post_event' | 'delayed'

export type AttackActor =
  | 'unprivileged_local_user'
  | 'sandboxed_process'
  | 'service_account'
  | 'local_administrator'
  | 'remote_attacker'
  | 'physical'
  | 'unknown'

export type VulnerabilityClass =
  | 'memory_safety'
  | 'privilege_escalation'
  | 'info_disclosure'
  | 'denial_of_service'
  | 'logic'
  | 'input_validation'
  | 'race_condition'
  | 'other'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type AttackVector = 'local' | 'adjacent' | 'network' | 'physical'
export type UserInteraction = 'none' | 'passive' | 'active'

// ---------- Entities ----------

export interface Project {
  id: string
  name: string
  description?: string
  authorized_use: boolean
  authorization_ref?: string | null
  tags: string[]
  created_at: string
}

export interface Target {
  id: string
  project_id: string
  name: string
  sha256: string
  size: number
  file_type: string
  authorized_use: boolean
  submitted_at: string
  path: string
}

export interface Observation {
  id: string
  target_id: string
  project_id: string
  category: string
  location: string | null
  description: string
  raw_excerpt: string | null
  source: 'static' | 'dynamic' | 'model_interpretation' | 'tool_output' | 'manual'
  source_tool: string | null
  source_method: string | null
  tool_version: string | null
  confidence: Confidence
  cross_validation: string[]
  created_at: string
}

export interface AttackSurfaceItem {
  id: string
  target_id: string
  project_id: string
  kind: string
  name: string
  address_or_offset: string | null
  parameters: Record<string, unknown>
  reachability: {
    required_privilege: string
    access_conditions: string[]
    interface_exposure: string | null
    namespace: string | null
    acl: string | null
    attack_actor: AttackActor
  }
  evidence_ids: string[]
  notes: string | null
}

export interface AttackSurface {
  id: string
  target_id: string
  project_id: string
  items: AttackSurfaceItem[]
  summary: string | null
}

export interface HypothesisScoreBreakdown {
  impact: number
  confidence: number
  reachability: number
  testability: number
  rule_score: number
  model_explanation: string
  human_calibration: number | null
  uncertainty: string | null
  feature_signals: Record<string, number>
}

export interface Hypothesis {
  id: string
  project_id: string
  target_id: string
  category: string
  location: string | null
  source: string | null
  sink: string | null
  description: string
  evidence_ids: string[]
  observation_ids: string[]
  attack_surface_item_ids: string[]
  related_attack_actor: AttackActor
  confidence: number
  priority: number
  priority_breakdown: HypothesisScoreBreakdown
  requires_human_review: boolean
  validation_required: boolean
  status: HypothesisStatus
  created_at: string
}

export interface ExperimentPlan {
  id: string
  hypothesis_id: string
  project_id: string
  environment_id: string
  setup: string[]
  inputs: string[]
  observation_points: string[]
  success_criteria: string[]
  failure_criteria: string[]
  rollback_requirement: string | null
  safety_constraints: string[]
  expected_telemetry: string[]
  timeout_seconds: number
  trial_count: number
  experiment_fingerprint: string | null
  status: ExperimentStatus
  risk_level: string
  created_at: string
}

export interface Execution {
  id: string
  experiment_id: string
  project_id: string
  environment_id: string
  vm_fingerprint: string
  snapshot_id: string | null
  tool_versions: Record<string, string>
  started_at: string | null
  finished_at: string | null
  status: 'pending' | 'running' | 'succeeded' | 'failed' | 'timeout' | 'cancelled' | 'inconclusive'
  artifact_refs: string[]
  log_ref: string | null
  error: string | null
  created_at: string
}

export interface Crash {
  id: string
  project_id: string
  execution_id: string
  hypothesis_id: string | null
  classification: string
  reproducible: boolean
  related_to_hypothesis: boolean
  dump_ref: string | null
  trace_ref: string | null
  summary: string
  created_at: string
}

export interface Evidence {
  id: string
  project_id: string
  target_id: string | null
  evidence_type: string
  producer_agent: string
  producer_run_id: string | null
  timestamp: string
  source_artifact_hash: string
  environment_snapshot_id: string | null
  tool_version: string | null
  model_version: string | null
  confidence: Confidence
  evidence_strength: EvidenceStrength
  related_hypothesis_id: string | null
  related_experiment_id: string | null
  related_crash_id: string | null
  qa_status: 'pending' | 'passed' | 'challenged' | 'rejected'
  raw_artifact_ref: string | null
  normalized_artifact_ref: string | null
  lineage_ids: string[]
  summary: string
}

export interface RootCause {
  id: string
  project_id: string
  crash_id: string | null
  category: string
  function: string | null
  instruction_region: string | null
  input_field: string | null
  trigger_condition: string
  reproducibility: string
  related_hypothesis_id: string | null
  evidence_ids: string[]
  created_at: string
}

export interface SecurityImpact {
  id: string
  project_id: string
  impact_type: string
  privilege_boundary_crossed: boolean
  confidentiality: 'none' | 'low' | 'high'
  integrity: 'none' | 'low' | 'high'
  availability: 'none' | 'low' | 'high'
  attack_vector: AttackVector
  required_privilege: string
  user_interaction: UserInteraction
  notes: string | null
  evidence_ids: string[]
  created_at: string
}

export interface ExploitabilityAssessment {
  id: string
  project_id: string
  exploitability_level: 'theoretical' | 'plausible' | 'demonstrated' | 'weaponized'
  controllability: 'none' | 'partial' | 'full'
  reliability: 'unreliable' | 'intermittent' | 'reliable'
  constraints: string[]
  mitigations_observed: string[]
  evidence_ids: string[]
  notes: string | null
  created_at: string
}

export interface CVSSVector {
  version: '3.1'
  vector: string
  base_score: number
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical'
}

export interface Finding {
  id: string
  project_id: string
  target_id: string
  title: string
  summary: string
  vulnerability_class: VulnerabilityClass
  cwe: string[]
  cvss: CVSSVector | null
  severity: Severity
  attack_vector: string
  required_privilege: string
  user_interaction: UserInteraction
  root_cause_id: string | null
  impact_id: string | null
  exploitability_id: string | null
  trigger_condition: string | null
  repro_steps: string[]
  evidence_ids: string[]
  crash_ids: string[]
  experiment_ids: string[]
  execution_ids: string[]
  telemetry_ids: string[]
  lineage_ids: string[]
  qa_status: string
  qa_review_id: string | null
  confidence: Confidence
  limitations: string[]
  remediation: string | null
  disclosure_status: string
  status: FindingStatus
  created_at: string
  updated_at: string
}

export interface QARuleHit {
  rule_id: string
  description: string
  passed: boolean
  detail: string | null
}

export interface QAReview {
  id: string
  project_id: string
  target_id: string | null
  finding_id: string | null
  hypothesis_id: string | null
  evidence_ids: string[]
  decision: QADecision
  rule_hits: QARuleHit[]
  llm_review_summary: string | null
  reasons: string[]
  created_at: string
}

export interface Approval {
  id: string
  project_id: string
  requester: string
  tool_run_id: string | null
  tool: string
  risk_level: RiskLevel
  justification: string
  parameters: Record<string, unknown>
  decision: 'pending' | 'approved' | 'rejected' | 'auto_approved' | 'expired'
  decided_by: string | null
  decided_at: string | null
  expires_at: string | null
  notes: string | null
  created_at: string
}

export interface ToolRun {
  id: string
  request_id: string
  idempotency_key: string
  project_id: string
  target_id: string | null
  tool: string
  parameters: Record<string, unknown>
  policy_context: Record<string, unknown>
  status: ToolRunStatus
  risk_level: RiskLevel
  approval_id: string | null
  timeout_seconds: number
  priority: string
  tool_version: string | null
  result: Record<string, unknown> | null
  error: string | null
  artifact_refs: Array<{
    sha256: string
    kind: string
    size: number
    location: string
    content_type: string | null
  }>
  parameters_hash: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  audit_log_ref: string | null
}

export interface AgentRun {
  id: string
  project_id: string
  research_id: string | null
  agent: string
  node: string
  started_at: string
  finished_at: string | null
  status: string
  inputs: Record<string, unknown>
  outputs: Record<string, unknown>
  model_version: string | null
  prompt_ref: string | null
  response_ref: string | null
  error: string | null
}

export interface VisibilityResult {
  id: string
  project_id: string
  execution_id: string
  process_event_visible: boolean
  image_load_visible: boolean
  driver_load_visible: boolean
  file_event_visible: boolean
  registry_event_visible: boolean
  network_event_visible: boolean
  kernel_callback_visible: boolean
  etw_available: boolean
  security_product_logs_available: boolean
  event_complete: boolean
  timestamp_aligned: boolean
  passed: boolean
  reasons: string[]
  created_at: string
}

export interface DetectionResult {
  id: string
  project_id: string
  execution_id: string
  behavior_confirmed: boolean
  telemetry_collected: boolean
  product_version: string | null
  product_policy: string | null
  observed_alert: boolean
  observed_block: boolean
  observed_telemetry_only: boolean
  detection_stage: DetectionStage
  product_detected: boolean | null
  verdict: DetectionVerdict
  detection_confidence: Confidence
  inconclusive_reason: string | null
  trials_total: number
  trials_detected: number
  trials_inconclusive: number
  detection_rate: number
  env_anomaly_rate: number
  telemetry_missing_rate: number
  positive_control_passed: boolean | null
  negative_control_passed: boolean | null
  evidence_ids: string[]
  created_at: string
}

export interface RobustnessResult {
  id: string
  project_id: string
  detection_id: string | null
  baseline_detection_rate: number
  per_variant_detection_rate: Record<string, number>
  robustness_score: 'high' | 'medium' | 'low'
  weak_dimension: string | null
  variant_ids: string[]
  evidence_ids: string[]
  notes: string | null
  created_at: string
}

// ---------- Research (run record) ----------

export interface ResearchRun {
  research_id: string
  project_id: string
  target_id: string
  status: Status
  current_phase: string
  current_node: string
  started_at: string | null
  completed_at: string | null
  finding_ids: string[]
  evidence_ids: string[]
  hypothesis_ids: string[]
  qa_review_ids: string[]
  report: ResearchReport | null
  error: string | null
}

export interface ResearchReport {
  id: string
  research_id: string
  title: string
  executive_summary: string
  sections: { heading: string; body: string }[]
  finding_ids: string[]
  limitations: string[]
}

// ---------- Lineage ----------

export interface LineageNode {
  id: string
  type:
    | 'project'
    | 'target'
    | 'observation'
    | 'hypothesis'
    | 'experiment'
    | 'execution'
    | 'crash'
    | 'evidence'
    | 'finding'
    | 'qa_review'
    | 'research'
    | 'visibility'
    | 'detection'
    | 'robustness'
    | 'tool_run'
  label: string
}

export interface Lineage {
  ids: string[]
  nodes: LineageNode[]
}

export interface EvidenceChain {
  finding: Finding
  evidences: Evidence[]
  lineage: Lineage
}

// ---------- Dashboard ----------

export interface DashboardStats {
  projects: number
  targets: number
  research_runs: number
  hypotheses: number
  evidence: number
  findings: number
  qa_reviews: number
  tool_runs: number
  pending_approvals: number
}

export interface LabHealth {
  provider: string
  passed: boolean
  vm_fingerprint: string | null
  checks: Record<string, string>
  notes: string
}

export interface HealthStatus {
  status: 'ok' | string
  version: string
  data_dir: string
  artifacts_dir: string
  auth_mode: string
  llm_provider: string
  lab_provider: string
  langgraph: string
}

// ---------- UI helpers ----------

export interface LineageNodeKindMeta {
  kind: LineageNode['type']
  label: string
  color: string // tailwind class fragment
}

export const LINEAGE_KINDS: LineageNodeKindMeta[] = [
  { kind: 'project', label: 'Project', color: 'bg-sky-500/15 text-sky-300 border-sky-500/30' },
  { kind: 'target', label: 'Target', color: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30' },
  { kind: 'observation', label: 'Observation', color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' },
  { kind: 'hypothesis', label: 'Hypothesis', color: 'bg-violet-500/15 text-violet-300 border-violet-500/30' },
  { kind: 'experiment', label: 'Experiment', color: 'bg-amber-500/15 text-amber-300 border-amber-500/30' },
  { kind: 'execution', label: 'Execution', color: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  { kind: 'crash', label: 'Crash', color: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
  { kind: 'evidence', label: 'Evidence', color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' },
  { kind: 'finding', label: 'Finding', color: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30' },
  { kind: 'qa_review', label: 'QA Review', color: 'bg-teal-500/15 text-teal-300 border-teal-500/30' },
  { kind: 'research', label: 'Research', color: 'bg-blue-500/15 text-blue-300 border-blue-500/30' },
  { kind: 'visibility', label: 'Visibility', color: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  { kind: 'detection', label: 'Detection', color: 'bg-pink-500/15 text-pink-300 border-pink-500/30' },
  { kind: 'robustness', label: 'Robustness', color: 'bg-lime-500/15 text-lime-300 border-lime-500/30' },
  { kind: 'tool_run', label: 'Tool Run', color: 'bg-slate-500/15 text-slate-300 border-slate-500/30' },
]

export const EVIDENCE_STRENGTH_META: Record<EvidenceStrength, { label: string; desc: string; color: string }> = {
  E0: { label: 'E0', desc: 'LLM opinion (not evidence)', color: 'bg-slate-500/15 text-slate-300 border-slate-500/30' },
  E1: { label: 'E1', desc: 'Static observation', color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' },
  E2: { label: 'E2', desc: 'Dynamic observation', color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' },
  E3: { label: 'E3', desc: 'Reproducible signal', color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' },
  E4: { label: 'E4', desc: 'Crash / Dump', color: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
  E5: { label: 'E5', desc: 'Root cause linked', color: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
  E6: { label: 'E6', desc: 'Security impact confirmed', color: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30' },
  E7: { label: 'E7', desc: 'QA passed', color: 'bg-teal-500/15 text-teal-300 border-teal-500/30' },
}

export const SEVERITY_META: Record<Severity, { color: string; label: string }> = {
  info: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'INFO' },
  low: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'LOW' },
  medium: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'MED' },
  high: { color: 'bg-orange-500/15 text-orange-300 border-orange-500/30', label: 'HIGH' },
  critical: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'CRIT' },
}

export const FINDING_STATUS_META: Record<FindingStatus, { color: string; label: string }> = {
  candidate: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'Candidate' },
  evidence_review: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'Evidence Review' },
  qa_pass: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'QA Pass' },
  human_approved: { color: 'bg-teal-500/15 text-teal-300 border-teal-500/30', label: 'Human Approved' },
  confirmed: { color: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30', label: 'Confirmed' },
  false_positive: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'False Positive' },
  needs_human: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'Needs Human' },
  archived: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'Archived' },
  disclosed: { color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30', label: 'Disclosed' },
}

export const QA_DECISION_META: Record<QADecision, { color: string; label: string }> = {
  pass: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'PASS' },
  retry: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'RETRY' },
  reject: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'REJECT' },
  inconclusive: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'INCONCLUSIVE' },
}

export const TOOL_RUN_STATUS_META: Record<ToolRunStatus, { color: string; label: string }> = {
  queued: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'Queued' },
  running: { color: 'bg-sky-500/15 text-sky-300 border-sky-500/30', label: 'Running' },
  succeeded: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'Succeeded' },
  failed: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'Failed' },
  timeout: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'Timeout' },
  cancelled: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'Cancelled' },
  needs_approval: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'Needs Approval' },
  blocked_by_policy: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'Blocked' },
}

export const DETECTION_VERDICT_META: Record<DetectionVerdict, { color: string; label: string }> = {
  detected: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'DETECTED' },
  not_observed: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'NOT OBSERVED' },
  inconclusive: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'INCONCLUSIVE' },
  blocked: { color: 'bg-sky-500/15 text-sky-300 border-sky-500/30', label: 'BLOCKED' },
}

export const RISK_META: Record<RiskLevel, { color: string; label: string }> = {
  low: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'LOW' },
  medium: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'MED' },
  high: { color: 'bg-orange-500/15 text-orange-300 border-orange-500/30', label: 'HIGH' },
  extreme: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'EXTREME' },
}

export const ATTACK_ACTOR_META: Record<AttackActor, { color: string; label: string }> = {
  unprivileged_local_user: { color: 'bg-rose-500/15 text-rose-300 border-rose-500/30', label: 'Unprivileged Local' },
  sandboxed_process: { color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', label: 'Sandboxed' },
  service_account: { color: 'bg-sky-500/15 text-sky-300 border-sky-500/30', label: 'Service Account' },
  local_administrator: { color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30', label: 'Administrator' },
  remote_attacker: { color: 'bg-violet-500/15 text-violet-300 border-violet-500/30', label: 'Remote' },
  physical: { color: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30', label: 'Physical' },
  unknown: { color: 'bg-slate-500/15 text-slate-300 border-slate-500/30', label: 'Unknown' },
}
