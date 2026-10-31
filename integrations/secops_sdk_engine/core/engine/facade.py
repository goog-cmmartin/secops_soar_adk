from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


from engine.domain import (
    AlertInvestigation,
    AlertPlaybookStatus,
    PlaybookInstanceCard,
    PlaybookInstanceRun,
    PlaybookInstanceStep,
    CaseCommentRecord,
    CaseInvestigation,
    CaseListBatch,
    CaseSearchBatch,
    CaseSearchPrefix,
    CaseSearchQuery,
    CaseSearchResultItem,
    CaseStatus,
    CasePriority,
    CaseTimeline,
    CaseTimelineEvent,
    CaseTriageAssessment,
    CaseTriageBatch,
    CaseAiInvestigationResult,
    CaseWallRecord,
    CaseWallResult,
    CaseEvidenceItem,
    CaseEvidenceBatchResult,
    CaseDetectionCorrelationResult,
    TriageVerdict,
    CasePrecedentSummary,
    EntityPrecedentItem,
    CaseUpdateResult,
    CaseAlertUpdateResult,
    CaseAlertRecommendationJob,
    CaseAlertRecommendation,
    CaseSummary,
    RemediationAction,
    RemediationPlan,
    RemediationPlanBatch,
    AgenticResponseAction,
    AgenticResponsePlan,
    AgenticResponsePlanBatch,
    TinaInvestigation,
    TinaInvestigationBatch,
    DataTable,
    DataTableColumnInfo,
    DataTableHealthFinding,
    DataTableHealthReport,
    DataTableHealthStatus,
    DataTableRow,
    DataTableListResult,
    DataTableRowListResult,
    RuleSeverity,
    RuleCompilationDiagnostic,
    RuleValidationResult,
    RuleDeployment,
    RuleDeploymentListResult,
    RuleExecutionError,
    RuleExecutionErrorListResult,
    RuleSummary,
    RuleDetail,
    RuleListResult,
    RuleRevisionListResult,
    RuleHealthFinding,
    RuleHealthReport,
    RuleHealthStatus,
    ContentPackBatch,
    ContentPackDetail,
    ContentPackSearchQuery,
    ContentPackSummary,
    CuratedDetectionHealthReport,
    CuratedDetectionMetrics,
    CuratedRuleDetail,
    CuratedRuleSearchQuery,
    CuratedRuleSetBatch,
    CuratedRuleSetDeployment,
    CuratedRuleSetDetail,
    CuratedRuleSetSummary,
    CuratedRuleSummary,
    DetectionTuningReport,
    CorrelatedDetectionSample,
    CorrelatedSamplingBatch,
    MultiFactorExclusion,
    DetectionTuningProposal,
    DimensionCardinality,
    EntityCardinalityRecord,
    EntityCardinalityReport,
    FindingsRefinementBatch,
    FindingsRefinementSummary,
    FindingsRefinementTestResult,
    NoisyRuleRecord,
    NoisyRulesBatch,
    RuleCaseHistoryBatch,
    RuleCaseHistoryRecord,
    DashboardBatch,
    DashboardChart,
    DashboardDetail,
    DashboardHealthCheckResult,
    DashboardHealthFinding,
    DashboardHealthReport,
    DashboardHealthStatus,
    DashboardQuery,
    DashboardQueryResult,
    DashboardSearchQuery,
    DashboardSummary,
    EnterpriseIocBatch,
    EnterpriseIocMatch,
    EntityInvestigationReport,
    EntitySummaryResult,
    EntityType,
    EventInvestigation,
    EventReference,
    FeedBatch,
    FeedDetail,
    FeedHealthFinding,
    FeedHealthReport,
    FeedHealthStatus,
    FeedLogTypeBatch,
    FeedLogTypeSchema,
    FeedSearchQuery,
    FeedSourceTypeBatch,
    FeedSourceTypeSchema,
    FeedSummary,
    FieldFilter,
    FilterOperator,
    IntegrationBatch,
    IntegrationDetail,
    IntegrationInstance,
    IntegrationInstanceAffectedItems,
    IntegrationInstanceDeleteResult,
    IntegrationSearchQuery,
    IntegrationSummary,
    IntegrationType,
    JobBatch,
    JobDetail,
    JobExecutionLog,
    JobExecutionStatus,
    JobInstance,
    JobSearchQuery,
    JobSummary,
    LogProcessingPipelineBatch,
    LogProcessingPipelineDetail,
    LogProcessingPipelineSummary,
    LogTypeBatch,
    LogTypeSetting,
    LogTypeSummary,
    ManagedDomain,
    ManagedDomainSettings,
    MarketplaceAffectedItems,
    MarketplaceCommercialDiff,
    MarketplaceIntegrationBatch,
    MarketplaceIntegrationDetail,
    MarketplaceIntegrationReleaseNote,
    MarketplaceIntegrationSearchQuery,
    MarketplaceIntegrationSummary,
    ParserBatch,
    ParserDetail,
    ParserExtensionBatch,
    ParserExtensionDetail,
    ParserExtensionSummary,
    ParserHealthFinding,
    ParserHealthReport,
    ParserHealthStatus,
    ParserRunResult,
    ParserRunResultEntry,
    ParserSummary,
    PlaybookBatch,
    UnparsedLogDiagnostic,
    UnparsedLogsDiagnosticBatch,
    PlaybookCategory,
    PlaybookDetail,
    PlaybookSearchQuery,
    PlaybookSummary,
    PlaybookType,
    PreviewFeatureBatch,
    PreviewFeatureSummary,
    DataAccessScopeBatch,
    DataAccessScopeDetail,
    DataAccessScopeSummary,
    DataAccessLabelBatch,
    DataAccessLabelDetail,
    DataAccessLabelSummary,
    EnvironmentScopeBatch,
    EnvironmentScopeSummary,
    EnrichmentCombinationBatch,
    EnrichmentCombinationRecord,
    EnrichmentControlBatch,
    EnrichmentControlDetail,
    EnrichmentControlSummary,
    GeminiAgentSettings,
    EntityRiskConfig,
    TenantInstanceDetails,
    SoarUserSummary,
    SoarUserDetail,
    SoarUserBatch,
    SocRoleSummary,
    SocRoleBatch,
    CompanySettingProperty,
    CompanySettingsBatch,
    CaseTagDefinitionSummary,
    CaseTagDefinitionBatch,
    CaseStageDefinitionSummary,
    CaseStageDefinitionBatch,
    CaseCloseDefinitionSummary,
    CaseCloseDefinitionBatch,
    CaseCloseDynamicParameterSummary,
    CaseCloseDynamicParameterBatch,
    CaseTitleSettingProperty,
    CaseTitleSettingsBatch,
    CaseViewSummary,
    CaseViewDetail,
    CaseViewBatch,
    CustomFieldSummary,
    CustomFieldDetail,
    CustomFieldBatch,
    CalculatedFieldSummary,
    CalculatedFieldDetail,
    CalculatedFieldBatch,
    AlertGroupingCategoryDetail,
    AlertGroupingRuleSummary,
    AlertGroupingRuleDetail,
    AlertGroupingRuleBatch,
    AlertGroupingSettingProperty,
    AlertGroupingSettingsBatch,
    DataRetentionSettingProperty,
    DataRetentionSettingsBatch,
    EmailSettingProperty,
    EmailSettingsBatch,
    EnvironmentBatch,
    EnvironmentDetail,
    EnvironmentGroupBatch,
    EnvironmentGroupSummary,
    EnvironmentSummary,
    RemoteAgent,
    RemoteAgentBatch,
    RemoteAgentDetail,
    RemoteAgentSummary,
    SearchBatchResult,
    SearchRequest,
    SearchSession,
    StatsSearchRequest,
    StatsSearchResult,
    StatsSearchSession,
    UDMEvent,
    coerce_case_priority,
    coerce_case_status,
    coerce_entity_type,
    coerce_field_filters,
    coerce_playbook_type,
    SupportSettingProperty,
    SupportSettingsBatch,
    SoarNetworkSummary,
    SoarNetworkDetail,
    SoarNetworkBatch,
    SoarDomainSummary,
    SoarDomainDetail,
    SoarDomainBatch,
    SoarCustomListSummary,
    SoarCustomListDetail,
    SoarCustomListBatch,
    EmailTemplateSummary,
    EmailTemplateDetail,
    EmailTemplateBatch,
    EntitiesBlocklistSummary,
    EntitiesBlocklistDetail,
    EntitiesBlocklistBatch,
    SlaDefinitionSummary,
    SlaDefinitionDetail,
    SlaDefinitionBatch,
    RequestTemplateFieldDefinition,
    RequestTemplateSummary,
    RequestTemplateDetail,
    RequestTemplateBatch,
    SoarIngestionConnectorSummary,
    SoarIngestionConnectorDetail,
    SoarIngestionConnectorBatch,
    SoarWebhookSummary,
    SoarWebhookDetail,
    SoarWebhookBatch,
    ProductSourceStat,
    ProductSourceStatsBatch,
    RawLogValidationResult,
    RawLogSnippet,
    RawLogSearchResult,
    ValidationResult,
    GcpLogEntry,
    GcpLogQueryResult,
    MetricPoint,
    TimeSeriesData,
    ChronicleIngestionMetricsResult,
    GcpMonitoringQueryResult,
    ChronicleCustomRole,
    ChronicleIamMember,
    ChronicleIamRoleBinding,
    IdentityGovernanceReport,
    TimestampIntegrityReport,
    TimestampMetricRow,
    TimestampProgressionState,
    CloudStatusIncident,
    CloudStatusReport,
)
from engine.parsing import parse_id_list, parse_strict_bool
from engine.registry import WorkflowCapability, WorkflowRegistry, registry
from engine.workflows.alert_investigation import InvestigateAlertWorkflow
from engine.workflows.case_actions import (
    AssignCaseWorkflow,
    CreateCaseAlertRecommendationWorkflow,
    FetchCaseAlertRecommendationWorkflow,
    GetCaseAlertRecommendationWorkflow,
    GetCaseSummaryWorkflow,
    GetOrCreateCaseSummaryWorkflow,
    SetCaseAlertPriorityWorkflow,
    SetCaseIncidentWorkflow,
    SetCaseStageWorkflow,
    UpdateCaseAlertWorkflow,
    UpdateCaseWorkflow,
)
from engine.workflows.remediation_plan import (
    GetAgenticResponsePlanWorkflow,
    GetRemediationActionWorkflow,
    GetRemediationPlanWorkflow,
    ListRemediationActionsWorkflow,
    ListRemediationPlansWorkflow,
)
from engine.workflows.tina_investigation import (
    GetAlertLatestTinaInvestigationWorkflow,
    GetTinaInvestigationWorkflow,
    ListTinaInvestigationsWorkflow,
)
from engine.workflows.case_investigation import (
    AddCaseCommentWorkflow,
    InvestigateCaseWorkflow,
)
from engine.workflows.case_list import ListCasesWorkflow
from engine.workflows.case_search import SearchCasesWorkflow
from engine.workflows.case_triage import (
    CaseTriageWorkflow,
    GetCaseTimelineWorkflow,
    OrchestrateCaseTriageWorkflow,
)
from engine.workflows.case_ai_investigation import InvestigateCaseWithAIWorkflow
from engine.workflows.case_wall import (
    GetCaseWallWorkflow,
    ListCaseCommentsWorkflow,
)
from engine.workflows.case_evidence import (
    AttachCaseEvidenceWorkflow,
    DetachCaseEvidenceWorkflow,
)
from engine.workflows.correlate_silent_detections import CorrelateSilentDetectionsWorkflow
from engine.workflows.content_pack import (
    GetContentPackDetailWorkflow,
    ListContentPackCategoriesWorkflow,
    SearchContentPacksWorkflow,
)
from engine.workflows.curated_detections import (
    GetCuratedDetectionMetricsWorkflow,
    GetCuratedRuleDetailWorkflow,
    GetCuratedRuleSetDetailWorkflow,
    ListCuratedRuleSetDeploymentsWorkflow,
    ListCuratedRuleSetsWorkflow,
    ListCuratedRulesWorkflow,
    SearchCuratedRuleSetsWorkflow,
    SetCuratedRuleSetDeploymentWorkflow,
)
from engine.workflows.detection_tuning import (
    AnalyzeEntityCardinalityWorkflow,
    CrossReferenceRuleCasesWorkflow,
    DiagnoseAndTuneDetectionWorkflow,
    FindTopNoisyRulesWorkflow,
    ManageFindingsRefinementsWorkflow,
    QueryRuleCaseEnvironmentsWorkflow,
    SampleDetectionEventsWorkflow,
    SynthesizeMultiFactorExclusionWorkflow,
    SynthesizeTuningProposalWorkflow,
    TestFindingsRefinementWorkflow,
    translate_to_udm_refinement,
)
from engine.workflows.dashboards import (
    run_dashboard_health_check,
    AddDashboardChartWorkflow,
    CreateDashboardWorkflow,
    DeleteDashboardWorkflow,
    DuplicateDashboardWorkflow,
    ExecuteDashboardQueryWorkflow,
    GetDashboardDetailWorkflow,
    RemoveDashboardChartWorkflow,
    SearchDashboardsWorkflow,
    UpdateDashboardChartWorkflow,
    UpdateDashboardWorkflow,
    ValidateDashboardQueryWorkflow,
)
from engine.workflows.dashboard_health import AuditDashboardHealthWorkflow
from engine.workflows.data_rbac import (
    GetDataAccessLabelWorkflow,
    GetDataAccessScopeWorkflow,
    SearchDataAccessLabelsWorkflow,
    SearchDataAccessScopesWorkflow,
    SearchEnvironmentScopesWorkflow,
)
from engine.entity_detector import DetectedEntity, EntityCategory, detect_entity
from engine.workflows.enrichment import (
    GetEnrichmentControlWorkflow,
    ListEnrichmentCombinationsWorkflow,
    SearchEnrichmentControlsWorkflow,
)
from engine.workflows.entity_search import (
    InvestigateEntityWorkflow,
    SearchEntityGraphWorkflow,
    SearchEnterpriseIocsWorkflow,
    SummarizeEntityWorkflow,
)
from engine.workflows.feed import (
    GetFeedDetailWorkflow,
    ListFeedLogTypeSchemasWorkflow,
    ListFeedSourceTypeSchemasWorkflow,
    SearchFeedsWorkflow,
)
from engine.workflows.feed_health import AuditFeedHealthWorkflow
from engine.workflows.integration import (
    DeleteIntegrationInstanceWorkflow,
    FetchIntegrationInstanceAffectedItemsWorkflow,
    GetIntegrationDetailWorkflow,
    ListIntegrationInstancesWorkflow,
    ListRemoteAgentsWorkflow,
    SearchIntegrationsWorkflow,
)
from engine.workflows.investigate_event import InvestigateEventWorkflow
from engine.workflows.job import (
    CreateJobInstanceWorkflow,
    GetJobDetailWorkflow,
    GetJobInstanceLogsWorkflow,
    ListJobInstancesWorkflow,
    SearchJobsWorkflow,
    UpdateJobInstanceWorkflow,
    UpdateJobWorkflow,
)
from engine.workflows.marketplace_integrations import (
    GetMarketplaceIntegrationAffectedItemsWorkflow,
    GetMarketplaceIntegrationDetailWorkflow,
    GetMarketplaceIntegrationDiffWorkflow,
    SearchMarketplaceIntegrationsWorkflow,
)
from engine.workflows.parser import (
    FindUnparsedLogsAndDiagnoseWorkflow,
    GetLogTypeSettingWorkflow,
    GetParserDetailWorkflow,
    GetParserExtensionDetailWorkflow,
    ListLogTypesWorkflow,
    RunParserWorkflow,
    SearchParserExtensionsWorkflow,
    SearchParsersWorkflow,
)
from engine.workflows.parser_health import AuditParserHealthWorkflow
from engine.workflows.playbook import (
    DeletePlaybooksWorkflow,
    GetAlertPlaybookInstancesWorkflow,
    GetPlaybookWorkflow,
    ListPlaybookCategoriesWorkflow,
    SavePlaybookWorkflow,
    SearchPlaybooksWorkflow,
    UpdatePlaybookWidgetWorkflow,
)
from engine.workflows.playbook_health import AuditPlaybookHealthWorkflow
from engine.workflows.playbook_decay import AuditPlaybookDecayWorkflow
from engine.workflows.timestamp_integrity import TimestampIntegrityWorkflow
from engine.workflows.preview_feature import (
    GetPreviewFeatureWorkflow,
    ListPreviewFeaturesWorkflow,
)
from engine.workflows.raw_log_search import (
    QueryProductSourceStatsWorkflow,
    SearchRawLogsWorkflow,
    ValidateRawLogQueryWorkflow,
)
from engine.workflows.refine_search import (
    RefineSearchWorkflow,
    SearchFromEntityWorkflow,
)
from engine.workflows.search_udm import SearchUDMWorkflow
from engine.workflows.search_udm_stats import SearchUDMStatsWorkflow
from engine.workflows.udm_aggregate import AggregateUdmWorkflow
from engine.workflows.udm_query_assist import FindUdmFieldValuesWorkflow, TranslateUdmQueryWorkflow
from engine.domain import UdmAggregateResult, UdmFieldValueMatches, UdmQueryTranslation
from engine.workflows.siem_settings import (
    GetAgentSettingsWorkflow,
    GetEntityRiskConfigWorkflow,
    GetLogProcessingPipelineDetailWorkflow,
    GetManagedDomainSettingsWorkflow,
    GetTenantInstanceWorkflow,
    SearchLogProcessingPipelinesWorkflow,
)
from engine.workflows.soar_settings import (
    GetCompanySettingsWorkflow,
    GetDataRetentionSettingsWorkflow,
    GetEmailSettingsWorkflow,
    GetEnvironmentWorkflow,
    GetRemoteAgentWorkflow,
    GetSoarUserWorkflow,
    GetSupportSettingsWorkflow,
    ListSocRolesWorkflow,
    SearchEnvironmentGroupsWorkflow,
    SearchEnvironmentsWorkflow,
    SearchRemoteAgentsWorkflow,
    SearchSoarUsersWorkflow,
    SearchSoarNetworksWorkflow,
    GetSoarNetworkWorkflow,
    SearchSoarDomainsWorkflow,
    GetSoarDomainWorkflow,
    SearchSoarCustomListsWorkflow,
    GetSoarCustomListWorkflow,
    SearchEmailTemplatesWorkflow,
    GetEmailTemplateWorkflow,
    SearchEntitiesBlocklistsWorkflow,
    GetEntitiesBlocklistWorkflow,
    SearchSlaDefinitionsWorkflow,
    GetSlaDefinitionWorkflow,
    SearchRequestTemplatesWorkflow,
    GetRequestTemplateWorkflow,
    SearchSoarIngestionConnectorsWorkflow,
    GetSoarIngestionConnectorWorkflow,
    SearchSoarWebhooksWorkflow,
    GetSoarWebhookWorkflow,
)
from engine.workflows.case_config import (
    GetAlertGroupingRuleWorkflow,
    GetAlertGroupingSettingsWorkflow,
    GetCalculatedFieldWorkflow,
    GetCaseTitleSettingsWorkflow,
    GetCaseViewWorkflow,
    GetCustomFieldWorkflow,
    ListCaseCloseDefinitionsWorkflow,
    ListCaseCloseDynamicParametersWorkflow,
    ListCaseStageDefinitionsWorkflow,
    SearchAlertGroupingRulesWorkflow,
    SearchCalculatedFieldsWorkflow,
    SearchCaseTagDefinitionsWorkflow,
    SearchCaseViewsWorkflow,
    SearchCustomFieldsWorkflow,
)
from engine.workflows.data_tables import (
    ListDataTablesWorkflow,
    GetDataTableWorkflow,
    CreateDataTableWorkflow,
    PatchDataTableWorkflow,
    DeleteDataTableWorkflow,
    ListDataTableRowsWorkflow,
    AddDataTableRowsWorkflow,
    DeleteDataTableRowWorkflow,
)
from engine.workflows.data_table_health import (
    AuditDataTableHealthWorkflow,
)
from engine.workflows.detection_rules import (
    ListRulesWorkflow,
    GetRuleWorkflow,
    VerifyRuleWorkflow,
    CreateRuleWorkflow,
    PatchRuleWorkflow,
    DeleteRuleWorkflow,
    ListRuleRevisionsWorkflow,
    ListRuleDeploymentsWorkflow,
    GetRuleDeploymentWorkflow,
    UpdateRuleDeploymentWorkflow,
    ListRuleErrorsWorkflow,
)
from engine.workflows.rule_health import AuditRuleHealthWorkflow
from engine.workflows.gcp_logging_query import GcpLoggingQueryWorkflow
from engine.workflows.gcp_monitoring_query import GcpMonitoringQueryWorkflow
from engine.workflows.identity_governance import IdentityGovernanceWorkflow
from engine.workflows.rule_decay import (
    AuditRuleDecayWorkflow,
    QueryRuleDetectionCountsWorkflow,
    QueryRuleDetectionSeriesWorkflow,
    AuditUdmFieldPopulationWorkflow,
    calculate_decay_score,
    extract_udm_fields_from_yaral,
)
from engine.domain import RuleDecayAssessment, RuleDecayReport
from engine.domain import (
    CuratedRuleListResult,
    CuratedRuleSetDeploymentListResult,
    CuratedRuleSetListResult,
    RuleCaseEnvironmentResult,
    RuleDetectionSeriesResult,
)
from engine.workflows.rule_conflict import (
    AuditRuleConflictWorkflow,
    BatchAuditRuleConflictsWorkflow,
    FindSimilarRulesWorkflow,
    SyncRuleEmbeddingsWorkflow,
    calculate_conflict_overlap_score,
    synthesize_rule_summary,
)
from engine.domain import (
    RuleConflictType,
    ConflictSeverityTier,
    RuleConflictPair,
    RuleConflictAuditResult,
    BatchRuleConflictAuditResult,
    RuleAuditFinding,
    RuleAuditReport,
    RuleSourceType,
    LogCostAnalysisReport,
    LogTypeCostMetric,
    FinOpsRecommendation,
    LogPricingTier,
    IngestionLabelMetric,
    NamespaceMetric,
    UntaggedTelemetrySummary,
    DataRbacLabelReference,
    NamespaceLabelHygieneFinding,
    NamespaceLabelAnalysisReport,
    IdentityFidelityMetric,
    EntityGraphSource,
    LogSourceVolumeMetric,
    TenantTelemetryProfile,
    ShiftBriefing,
    KnowledgeSnapshot,
    MitreCoverageAssessment,
)
from engine.workflows.rule_audit import AuditRulesWorkflow
from engine.workflows.log_cost import AnalyzeLogCostWorkflow, GetLatestLogCostWorkflow
from engine.workflows.namespace_labels import (
    AnalyzeIngestionLabelsWorkflow,
    AnalyzeNamespacesWorkflow,
    AuditDataRbacAlignmentWorkflow,
    AnalyzeNamespaceLabelsCompositeWorkflow,
)
from engine.workflows.tenant_profiling import TenantProfilingWorkflow
from engine.workflows.briefing_aggregation import (
    compute_shift_delta,
    compute_knowledge_snapshot,
)
from engine.workflows.mitre_attack import (
    SyncMitreRulesWorkflow,
    AnalyzeMitreCoverageWorkflow,
    GenerateMitreReportWorkflow,
)
from engine.mitre_catalog import MitreCatalog




def _normalize_case_id(case_id: Union[str, int]) -> str:
    """Normalizes case identifier to string, stripping whitespace and URI/resource prefixes."""
    s = str(case_id).strip()
    return s.split("/")[-1] if "/" in s else s


def _resolve_time_window(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    lookback_hours: int = 24,
) -> Tuple[str, str]:
    """Resolves start_time and end_time, defaulting omitted bounds to a UTC lookback window."""
    if start_time is not None and end_time is not None:
        return start_time, end_time
    now = datetime.now(timezone.utc)
    resolved_end = end_time if end_time is not None else now.strftime("%Y-%m-%dT%H:%M:%SZ")
    resolved_start = (
        start_time
        if start_time is not None
        else (now - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    return resolved_start, resolved_end


class SecOpsEngine:
    """The central workflow engine exposing high-level SecOps domain capabilities."""

    def __init__(
        self,
        adapter: Optional[Any] = None,
        custom_registry: Optional[WorkflowRegistry] = None,
        evidence_store: Optional[Any] = None,
    ):
        if adapter is None:
            from adapters.google_secops import GoogleSecOpsAdapter
            adapter = GoogleSecOpsAdapter()
        self.adapter = adapter
        self.registry = custom_registry if custom_registry is not None else WorkflowRegistry()
        self.evidence_store = evidence_store
        self._wf_cache: Dict[str, Any] = {}

        # Register default capabilities
        self._register_default_capabilities()
        if custom_registry is None:
            for cap in self.registry.list_capabilities():
                registry.register(cap)

    _WORKFLOW_MAP = {
        "_search_udm_wf": lambda e: SearchUDMWorkflow(e.adapter),
        "_search_udm_stats_wf": lambda e: SearchUDMStatsWorkflow(e.adapter),
        "_aggregate_udm_wf": lambda e: AggregateUdmWorkflow(e.adapter),
        "_find_udm_field_values_wf": lambda e: FindUdmFieldValuesWorkflow(e.adapter),
        "_translate_udm_query_wf": lambda e: TranslateUdmQueryWorkflow(e.adapter),
        "_query_product_source_stats_wf": lambda e: QueryProductSourceStatsWorkflow(e.adapter),
        "_validate_raw_log_query_wf": lambda e: ValidateRawLogQueryWorkflow(e.adapter),
        "_search_raw_logs_wf": lambda e: SearchRawLogsWorkflow(e.adapter),
        "_investigate_event_wf": lambda e: InvestigateEventWorkflow(e.adapter),
        "_refine_search_wf": lambda e: RefineSearchWorkflow(e._search_udm_wf),
        "_search_from_entity_wf": lambda e: SearchFromEntityWorkflow(e._search_udm_wf),
        "_investigate_case_wf": lambda e: InvestigateCaseWorkflow(e.adapter),
        "_add_case_comment_wf": lambda e: AddCaseCommentWorkflow(e.adapter),
        "_list_case_comments_wf": lambda e: ListCaseCommentsWorkflow(e.adapter),
        "_get_case_wall_wf": lambda e: GetCaseWallWorkflow(e.adapter),
        "_attach_case_evidence_wf": lambda e: AttachCaseEvidenceWorkflow(e.adapter),
        "_detach_case_evidence_wf": lambda e: DetachCaseEvidenceWorkflow(e.adapter),
        "_correlate_silent_detections_wf": lambda e: CorrelateSilentDetectionsWorkflow(e.adapter),
        "_update_case_wf": lambda e: UpdateCaseWorkflow(e.adapter),
        "_assign_case_wf": lambda e: AssignCaseWorkflow(e.adapter),
        "_set_case_stage_wf": lambda e: SetCaseStageWorkflow(e.adapter),
        "_set_case_incident_wf": lambda e: SetCaseIncidentWorkflow(e.adapter),
        "_update_case_alert_wf": lambda e: UpdateCaseAlertWorkflow(e.adapter),
        "_set_case_alert_priority_wf": lambda e: SetCaseAlertPriorityWorkflow(e.adapter),
        "_create_case_alert_recommendation_wf": lambda e: CreateCaseAlertRecommendationWorkflow(e.adapter),
        "_fetch_case_alert_recommendation_wf": lambda e: FetchCaseAlertRecommendationWorkflow(e.adapter),
        "_get_case_alert_recommendation_wf": lambda e: GetCaseAlertRecommendationWorkflow(e.adapter),
        "_get_or_create_case_summary_wf": lambda e: GetOrCreateCaseSummaryWorkflow(e.adapter),
        "_get_case_summary_wf": lambda e: GetCaseSummaryWorkflow(e.adapter),
        "_list_remediation_plans_wf": lambda e: ListRemediationPlansWorkflow(e.adapter),
        "_get_remediation_plan_wf": lambda e: GetRemediationPlanWorkflow(e.adapter),
        "_get_agentic_response_plan_wf": lambda e: GetAgenticResponsePlanWorkflow(
            e.adapter,
            list_workflow=e._list_remediation_plans_wf,
            get_workflow=e._get_remediation_plan_wf,
        ),
        "_list_remediation_actions_wf": lambda e: ListRemediationActionsWorkflow(e.adapter),
        "_get_remediation_action_wf": lambda e: GetRemediationActionWorkflow(e.adapter),
        "_list_tina_investigations_wf": lambda e: ListTinaInvestigationsWorkflow(e.adapter),
        "_get_tina_investigation_wf": lambda e: GetTinaInvestigationWorkflow(e.adapter),
        "_get_alert_latest_tina_investigation_wf": lambda e: GetAlertLatestTinaInvestigationWorkflow(e.adapter),
        "_investigate_alert_wf": lambda e: InvestigateAlertWorkflow(e.adapter),
        "_search_cases_wf": lambda e: SearchCasesWorkflow(e.adapter),
        "_list_cases_wf": lambda e: ListCasesWorkflow(e.adapter),
        "_case_triage_wf": lambda e: CaseTriageWorkflow(e.adapter),
        "_get_case_timeline_wf": lambda e: GetCaseTimelineWorkflow(e.adapter),
        "_orchestrate_case_triage_wf": lambda e: OrchestrateCaseTriageWorkflow(e.adapter, triage_workflow=e._case_triage_wf),
        "_case_ai_investigate_wf": lambda e: InvestigateCaseWithAIWorkflow(
            e.adapter,
            investigate_workflow=e._investigate_case_wf,
            case_summary_workflow=e._get_case_summary_wf,
            search_udm_workflow=e._search_udm_wf,
            incident_workflow=e._set_case_incident_wf,
            update_alert_workflow=e._update_case_alert_wf,
            add_comment_workflow=e._add_case_comment_wf,
        ),
        "_search_playbooks_wf": lambda e: SearchPlaybooksWorkflow(e.adapter),
        "_get_playbook_wf": lambda e: GetPlaybookWorkflow(e.adapter),
        "_list_playbook_cats_wf": lambda e: ListPlaybookCategoriesWorkflow(e.adapter),
        "_save_playbook_wf": lambda e: SavePlaybookWorkflow(e.adapter),
        "_update_playbook_widget_wf": lambda e: UpdatePlaybookWidgetWorkflow(e.adapter),
        "_delete_playbooks_wf": lambda e: DeletePlaybooksWorkflow(e.adapter),
        "_alert_playbook_instances_wf": lambda e: GetAlertPlaybookInstancesWorkflow(e.adapter),
        "_audit_soar_playbook_health_wf": lambda e: AuditPlaybookHealthWorkflow(e),
        "_audit_playbook_decay_wf": lambda e: AuditPlaybookDecayWorkflow(e),
        "_timestamp_integrity_wf": lambda e: TimestampIntegrityWorkflow(e.adapter, getattr(e, "evidence_store", None)),
        "_search_integrations_wf": lambda e: SearchIntegrationsWorkflow(e.adapter),
        "_get_integration_wf": lambda e: GetIntegrationDetailWorkflow(e.adapter),
        "_list_integration_instances_wf": lambda e: ListIntegrationInstancesWorkflow(e.adapter),
        "_get_integration_instance_affected_items_wf": lambda e: FetchIntegrationInstanceAffectedItemsWorkflow(e.adapter),
        "_delete_integration_instance_wf": lambda e: DeleteIntegrationInstanceWorkflow(
            e.adapter,
            affected_items_workflow=e._get_integration_instance_affected_items_wf,
        ),
        "_list_remote_agents_wf": lambda e: ListRemoteAgentsWorkflow(e.adapter),
        "_search_jobs_wf": lambda e: SearchJobsWorkflow(e.adapter),
        "_get_job_wf": lambda e: GetJobDetailWorkflow(e.adapter),
        "_list_job_instances_wf": lambda e: ListJobInstancesWorkflow(e.adapter),
        "_get_job_instance_logs_wf": lambda e: GetJobInstanceLogsWorkflow(e.adapter),
        "_update_job_wf": lambda e: UpdateJobWorkflow(e.adapter),
        "_update_job_instance_wf": lambda e: UpdateJobInstanceWorkflow(e.adapter),
        "_create_job_instance_wf": lambda e: CreateJobInstanceWorkflow(e.adapter),
        "_search_content_packs_wf": lambda e: SearchContentPacksWorkflow(e.adapter),
        "_get_content_pack_wf": lambda e: GetContentPackDetailWorkflow(e.adapter),
        "_list_content_pack_cats_wf": lambda e: ListContentPackCategoriesWorkflow(e.adapter),
        "_search_curated_rulesets_wf": lambda e: SearchCuratedRuleSetsWorkflow(e.adapter),
        "_list_curated_rule_set_deployments_wf": lambda e: ListCuratedRuleSetDeploymentsWorkflow(e.adapter),
        "_list_curated_rulesets_wf": lambda e: ListCuratedRuleSetsWorkflow(e.adapter),
        "_list_curated_rules_wf": lambda e: ListCuratedRulesWorkflow(e.adapter),
        "_get_curated_ruleset_wf": lambda e: GetCuratedRuleSetDetailWorkflow(e.adapter),
        "_get_curated_rule_wf": lambda e: GetCuratedRuleDetailWorkflow(e.adapter),
        "_get_curated_metrics_wf": lambda e: GetCuratedDetectionMetricsWorkflow(e.adapter),
        "_set_curated_ruleset_deployment_wf": lambda e: SetCuratedRuleSetDeploymentWorkflow(e.adapter),
        "_find_top_noisy_rules_wf": lambda e: FindTopNoisyRulesWorkflow(e.adapter),
        "_analyze_entity_cardinality_wf": lambda e: AnalyzeEntityCardinalityWorkflow(e.adapter),
        "_cross_reference_rule_cases_wf": lambda e: CrossReferenceRuleCasesWorkflow(e.adapter),
        "_rule_case_environments_wf": lambda e: QueryRuleCaseEnvironmentsWorkflow(e.adapter),
        "_test_findings_refinement_wf": lambda e: TestFindingsRefinementWorkflow(e.adapter),
        "_manage_findings_refinements_wf": lambda e: ManageFindingsRefinementsWorkflow(e.adapter),
        "_diagnose_and_tune_detection_wf": lambda e: DiagnoseAndTuneDetectionWorkflow(
            e.adapter,
            e._analyze_entity_cardinality_wf,
            e._cross_reference_rule_cases_wf,
            e._test_findings_refinement_wf,
        ),
        "_sample_detection_events_wf": lambda e: SampleDetectionEventsWorkflow(e.adapter),
        "_synthesize_multi_factor_exclusion_wf": lambda e: SynthesizeMultiFactorExclusionWorkflow(),
        "_synthesize_tuning_proposal_wf": lambda e: SynthesizeTuningProposalWorkflow(
            e.adapter,
            e._find_top_noisy_rules_wf,
            e._analyze_entity_cardinality_wf,
            e._sample_detection_events_wf,
            e._synthesize_multi_factor_exclusion_wf,
            e._test_findings_refinement_wf,
        ),
        "_search_marketplace_integrations_wf": lambda e: SearchMarketplaceIntegrationsWorkflow(e.adapter),
        "_get_marketplace_integration_wf": lambda e: GetMarketplaceIntegrationDetailWorkflow(e.adapter),
        "_get_marketplace_integration_diff_wf": lambda e: GetMarketplaceIntegrationDiffWorkflow(e.adapter),
        "_get_marketplace_affected_items_wf": lambda e: GetMarketplaceIntegrationAffectedItemsWorkflow(e.adapter),
        "_search_dashboards_wf": lambda e: SearchDashboardsWorkflow(e.adapter),
        "_get_dashboard_wf": lambda e: GetDashboardDetailWorkflow(e.adapter),
        "_create_dashboard_wf": lambda e: CreateDashboardWorkflow(e.adapter),
        "_update_dashboard_wf": lambda e: UpdateDashboardWorkflow(e.adapter),
        "_delete_dashboard_wf": lambda e: DeleteDashboardWorkflow(e.adapter),
        "_duplicate_dashboard_wf": lambda e: DuplicateDashboardWorkflow(e.adapter),
        "_add_dashboard_chart_wf": lambda e: AddDashboardChartWorkflow(e.adapter),
        "_update_dashboard_chart_wf": lambda e: UpdateDashboardChartWorkflow(e.adapter),
        "_remove_dashboard_chart_wf": lambda e: RemoveDashboardChartWorkflow(e.adapter),
        "_execute_dashboard_query_wf": lambda e: ExecuteDashboardQueryWorkflow(e.adapter),
        "_validate_dashboard_query_wf": lambda e: ValidateDashboardQueryWorkflow(e.adapter),
        "_audit_dashboard_health_wf": lambda e: AuditDashboardHealthWorkflow(e.adapter),
        "_get_managed_domains_wf": lambda e: GetManagedDomainSettingsWorkflow(e.adapter),
        "_search_feeds_wf": lambda e: SearchFeedsWorkflow(e.adapter),
        "_get_feed_wf": lambda e: GetFeedDetailWorkflow(e.adapter),
        "_audit_feed_health_wf": lambda e: AuditFeedHealthWorkflow(e.adapter),
        "_search_pipelines_wf": lambda e: SearchLogProcessingPipelinesWorkflow(e.adapter),
        "_get_pipeline_wf": lambda e: GetLogProcessingPipelineDetailWorkflow(e.adapter),
        "_list_feed_source_types_wf": lambda e: ListFeedSourceTypeSchemasWorkflow(e.adapter),
        "_list_feed_log_types_wf": lambda e: ListFeedLogTypeSchemasWorkflow(e.adapter),
        "_list_log_types_wf": lambda e: ListLogTypesWorkflow(e.adapter),
        "_search_parsers_wf": lambda e: SearchParsersWorkflow(e.adapter),
        "_get_parser_wf": lambda e: GetParserDetailWorkflow(e.adapter),
        "_run_parser_wf": lambda e: RunParserWorkflow(e.adapter),
        "_diagnose_unparsed_wf": lambda e: FindUnparsedLogsAndDiagnoseWorkflow(e.adapter),
        "_search_parser_extensions_wf": lambda e: SearchParserExtensionsWorkflow(e.adapter),
        "_get_parser_extension_wf": lambda e: GetParserExtensionDetailWorkflow(e.adapter),
        "_get_log_type_setting_wf": lambda e: GetLogTypeSettingWorkflow(e.adapter),
        "_audit_parser_health_wf": lambda e: AuditParserHealthWorkflow(e.adapter),
        "_list_preview_features_wf": lambda e: ListPreviewFeaturesWorkflow(e.adapter),
        "_get_preview_feature_wf": lambda e: GetPreviewFeatureWorkflow(e.adapter),
        "_search_data_access_scopes_wf": lambda e: SearchDataAccessScopesWorkflow(e.adapter),
        "_get_data_access_scope_wf": lambda e: GetDataAccessScopeWorkflow(e.adapter),
        "_search_data_access_labels_wf": lambda e: SearchDataAccessLabelsWorkflow(e.adapter),
        "_get_data_access_label_wf": lambda e: GetDataAccessLabelWorkflow(e.adapter),
        "_search_environment_scopes_wf": lambda e: SearchEnvironmentScopesWorkflow(e.adapter),
        "_list_enrichment_combinations_wf": lambda e: ListEnrichmentCombinationsWorkflow(e.adapter),
        "_search_enrichment_controls_wf": lambda e: SearchEnrichmentControlsWorkflow(e.adapter),
        "_get_enrichment_control_wf": lambda e: GetEnrichmentControlWorkflow(e.adapter),
        "_get_agent_settings_wf": lambda e: GetAgentSettingsWorkflow(e.adapter),
        "_get_entity_risk_config_wf": lambda e: GetEntityRiskConfigWorkflow(e.adapter),
        "_get_tenant_instance_wf": lambda e: GetTenantInstanceWorkflow(e.adapter),
        "_search_soar_users_wf": lambda e: SearchSoarUsersWorkflow(e.adapter),
        "_get_soar_user_wf": lambda e: GetSoarUserWorkflow(e.adapter),
        "_list_soc_roles_wf": lambda e: ListSocRolesWorkflow(e.adapter),
        "_get_company_settings_wf": lambda e: GetCompanySettingsWorkflow(e.adapter),
        "_search_case_tags_wf": lambda e: SearchCaseTagDefinitionsWorkflow(e.adapter),
        "_list_case_stages_wf": lambda e: ListCaseStageDefinitionsWorkflow(e.adapter),
        "_list_case_close_defs_wf": lambda e: ListCaseCloseDefinitionsWorkflow(e.adapter),
        "_list_case_close_params_wf": lambda e: ListCaseCloseDynamicParametersWorkflow(e.adapter),
        "_get_case_title_settings_wf": lambda e: GetCaseTitleSettingsWorkflow(e.adapter),
        "_search_case_views_wf": lambda e: SearchCaseViewsWorkflow(e.adapter),
        "_get_case_view_wf": lambda e: GetCaseViewWorkflow(e.adapter),
        "_search_custom_fields_wf": lambda e: SearchCustomFieldsWorkflow(e.adapter),
        "_get_custom_field_wf": lambda e: GetCustomFieldWorkflow(e.adapter),
        "_search_calculated_fields_wf": lambda e: SearchCalculatedFieldsWorkflow(e.adapter),
        "_get_calculated_field_wf": lambda e: GetCalculatedFieldWorkflow(e.adapter),
        "_search_alert_grouping_rules_wf": lambda e: SearchAlertGroupingRulesWorkflow(e.adapter),
        "_get_alert_grouping_rule_wf": lambda e: GetAlertGroupingRuleWorkflow(e.adapter),
        "_get_alert_grouping_settings_wf": lambda e: GetAlertGroupingSettingsWorkflow(e.adapter),
        "_get_data_retention_settings_wf": lambda e: GetDataRetentionSettingsWorkflow(e.adapter),
        "_search_environments_wf": lambda e: SearchEnvironmentsWorkflow(e.adapter),
        "_get_environment_wf": lambda e: GetEnvironmentWorkflow(e.adapter),
        "_search_environment_groups_wf": lambda e: SearchEnvironmentGroupsWorkflow(e.adapter),
        "_search_remote_agents_wf": lambda e: SearchRemoteAgentsWorkflow(e.adapter),
        "_get_remote_agent_wf": lambda e: GetRemoteAgentWorkflow(e.adapter),
        "_get_email_settings_wf": lambda e: GetEmailSettingsWorkflow(e.adapter),
        "_get_support_settings_wf": lambda e: GetSupportSettingsWorkflow(e.adapter),
        "_search_soar_networks_wf": lambda e: SearchSoarNetworksWorkflow(e.adapter),
        "_get_soar_network_wf": lambda e: GetSoarNetworkWorkflow(e.adapter),
        "_search_soar_domains_wf": lambda e: SearchSoarDomainsWorkflow(e.adapter),
        "_get_soar_domain_wf": lambda e: GetSoarDomainWorkflow(e.adapter),
        "_search_soar_custom_lists_wf": lambda e: SearchSoarCustomListsWorkflow(e.adapter),
        "_get_soar_custom_list_wf": lambda e: GetSoarCustomListWorkflow(e.adapter),
        "_search_email_templates_wf": lambda e: SearchEmailTemplatesWorkflow(e.adapter),
        "_get_email_template_wf": lambda e: GetEmailTemplateWorkflow(e.adapter),
        "_search_entities_blocklists_wf": lambda e: SearchEntitiesBlocklistsWorkflow(e.adapter),
        "_get_entities_blocklist_wf": lambda e: GetEntitiesBlocklistWorkflow(e.adapter),
        "_search_sla_definitions_wf": lambda e: SearchSlaDefinitionsWorkflow(e.adapter),
        "_get_sla_definition_wf": lambda e: GetSlaDefinitionWorkflow(e.adapter),
        "_search_request_templates_wf": lambda e: SearchRequestTemplatesWorkflow(e.adapter),
        "_get_request_template_wf": lambda e: GetRequestTemplateWorkflow(e.adapter),
        "_search_soar_ingestion_connectors_wf": lambda e: SearchSoarIngestionConnectorsWorkflow(e.adapter),
        "_get_soar_ingestion_connector_wf": lambda e: GetSoarIngestionConnectorWorkflow(e.adapter),
        "_search_soar_webhooks_wf": lambda e: SearchSoarWebhooksWorkflow(e.adapter),
        "_get_soar_webhook_wf": lambda e: GetSoarWebhookWorkflow(e.adapter),
        "_search_entity_graph_wf": lambda e: SearchEntityGraphWorkflow(e._search_udm_wf),
        "_search_enterprise_iocs_wf": lambda e: SearchEnterpriseIocsWorkflow(e.adapter),
        "_summarize_entity_wf": lambda e: SummarizeEntityWorkflow(e.adapter),
        "_investigate_entity_wf": lambda e: InvestigateEntityWorkflow(
            e._search_entity_graph_wf,
            e._search_from_entity_wf,
            e._search_enterprise_iocs_wf,
            e._search_cases_wf,
            e._summarize_entity_wf,
        ),
        "_list_data_tables_wf": lambda e: ListDataTablesWorkflow(e.adapter),
        "_get_data_table_wf": lambda e: GetDataTableWorkflow(e.adapter),
        "_create_data_table_wf": lambda e: CreateDataTableWorkflow(e.adapter),
        "_patch_data_table_wf": lambda e: PatchDataTableWorkflow(e.adapter),
        "_delete_data_table_wf": lambda e: DeleteDataTableWorkflow(e.adapter),
        "_list_data_table_rows_wf": lambda e: ListDataTableRowsWorkflow(e.adapter),
        "_add_data_table_rows_wf": lambda e: AddDataTableRowsWorkflow(e.adapter),
        "_delete_data_table_row_wf": lambda e: DeleteDataTableRowWorkflow(e.adapter),
        "_audit_data_table_health_wf": lambda e: AuditDataTableHealthWorkflow(e.adapter),
        "_list_rules_wf": lambda e: ListRulesWorkflow(e.adapter),
        "_get_rule_wf": lambda e: GetRuleWorkflow(e.adapter),
        "_verify_rule_wf": lambda e: VerifyRuleWorkflow(e.adapter),
        "_create_rule_wf": lambda e: CreateRuleWorkflow(e.adapter),
        "_patch_rule_wf": lambda e: PatchRuleWorkflow(e.adapter),
        "_delete_rule_wf": lambda e: DeleteRuleWorkflow(e.adapter),
        "_list_rule_revisions_wf": lambda e: ListRuleRevisionsWorkflow(e.adapter),
        "_list_rule_deployments_wf": lambda e: ListRuleDeploymentsWorkflow(e.adapter),
        "_get_rule_deployment_wf": lambda e: GetRuleDeploymentWorkflow(e.adapter),
        "_update_rule_deployment_wf": lambda e: UpdateRuleDeploymentWorkflow(e.adapter),
        "_list_rule_errors_wf": lambda e: ListRuleErrorsWorkflow(e.adapter),
        "_audit_rule_health_wf": lambda e: AuditRuleHealthWorkflow(e.adapter),
        "_query_cloud_logging_wf": lambda e: GcpLoggingQueryWorkflow(e.adapter),
        "_query_cloud_monitoring_wf": lambda e: GcpMonitoringQueryWorkflow(e.adapter),
        "_audit_rule_decay_wf": lambda e: AuditRuleDecayWorkflow(e.adapter),
        "_query_rule_detection_counts_wf": lambda e: QueryRuleDetectionCountsWorkflow(e.adapter),
        "_query_rule_detection_series_wf": lambda e: QueryRuleDetectionSeriesWorkflow(e.adapter),
        "_audit_udm_population_wf": lambda e: AuditUdmFieldPopulationWorkflow(e.adapter),
        "_audit_rule_conflict_wf": lambda e: AuditRuleConflictWorkflow(e.adapter),
        "_batch_audit_rule_conflicts_wf": lambda e: BatchAuditRuleConflictsWorkflow(e.adapter),
        "_find_similar_rules_wf": lambda e: FindSimilarRulesWorkflow(e.adapter),
        "_sync_rule_embeddings_wf": lambda e: SyncRuleEmbeddingsWorkflow(e.adapter),
        "_audit_rules_wf": lambda e: AuditRulesWorkflow(e.adapter),
        "_analyze_log_cost_wf": lambda e: AnalyzeLogCostWorkflow(e.adapter, store=e.evidence_store),
        "_get_latest_log_cost_wf": lambda e: GetLatestLogCostWorkflow(e.adapter, store=e.evidence_store),
        "_analyze_ingestion_labels_wf": lambda e: AnalyzeIngestionLabelsWorkflow(e.adapter, store=e.evidence_store),
        "_analyze_namespaces_wf": lambda e: AnalyzeNamespacesWorkflow(e.adapter, store=e.evidence_store),
        "_audit_data_rbac_alignment_wf": lambda e: AuditDataRbacAlignmentWorkflow(e.adapter, store=e.evidence_store),
        "_analyze_namespace_labels_wf": lambda e: AnalyzeNamespaceLabelsCompositeWorkflow(e.adapter, store=e.evidence_store),
        "_tenant_profiling_wf": lambda e: TenantProfilingWorkflow(e.adapter),
        "_sync_mitre_rules_wf": lambda e: SyncMitreRulesWorkflow(e.adapter, store=e.evidence_store),
        "_analyze_mitre_coverage_wf": lambda e: AnalyzeMitreCoverageWorkflow(e.adapter, store=e.evidence_store),
        "_generate_mitre_report_wf": lambda e: GenerateMitreReportWorkflow(e.adapter, store=e.evidence_store),
    }

    def __getattr__(self, name: str) -> Any:
        if name in self._WORKFLOW_MAP:
            if name not in self._wf_cache:
                self._wf_cache[name] = self._WORKFLOW_MAP[name](self)
            return self._wf_cache[name]
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def _register_default_capabilities(self) -> None:
        """Registers canonical workflow capabilities."""
        self.registry.register(
            WorkflowCapability(
                capability_id="search.udm",
                name="UDM Search (End-to-End)",
                description="Validates, initiates, incrementally streams, and manages lifecycle of UDM search queries.",
                category="search",
                handler=self.search_udm,
                mcp_tool_name="search_udm",
                composed=True,
                evidence_path="evidence/search/udm",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.udm.stats",
                name="UDM Stats Search (Aggregation & Analytics)",
                description="Validates, initiates, streams, and aggregates UDM statistics, match/outcome metrics, and multi-field grouping operations via LRO.",
                category="search",
                handler=self.search_udm_stats,
                mcp_tool_name="search_udm_stats",
                composed=False,
                evidence_path="evidence/search/udm_stats",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.udm.aggregate",
                name="Aggregate UDM Events (Bounded Grid)",
                description=(
                    "Counts UDM events grouped by 0-2 allow-listed fields and an optional hour/day "
                    "bucket in one synchronous dashboard SQL query; restricted, injection-safe filter "
                    "grammar; lookback <= 168 h, limit <= 2000 rows with truncation flag."
                ),
                category="search",
                handler=self.aggregate_udm,
                mcp_tool_name="aggregate_udm",
                composed=False,
                # Explicit: "aggregate" is not a known read verb. One dashboard
                # query with a hard row limit (<= 2000) -> bounded query.
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/search/udm_aggregate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.udm.field_values",
                name="Find UDM Field Values",
                description="Finds UDM field paths whose recent values match a text fragment (:findUdmFieldValues), for query autocomplete.",
                category="search",
                handler=self.find_udm_field_values,
                mcp_tool_name="find_udm_field_values",
                composed=False,
                # Explicit: read-only GET; one page capped by page_size (<= 1000).
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/search/udm_field_values",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.udm.translate",
                name="Translate Natural Language to UDM Query",
                description="Translates natural-language text into a UDM search query and optional time range (:translateUdmQuery). Does not run the query.",
                category="search",
                handler=self.translate_udm_query,
                mcp_tool_name="translate_udm_query",
                composed=False,
                # Explicit: read-only POST returning one translation.
                kind="query",
                cardinality="single",
                evidence_path="evidence/search/udm_translate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="log.product_sources.stats",
                name="Query Product Source Statistics",
                description="Queries product log sources, data ingestion volumes, and active sources in the tenant.",
                category="log",
                handler=self.query_product_source_stats,
                mcp_tool_name="query_product_source_stats",
                composed=False,
                evidence_path="evidence/log/product_sources_stats",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="log.query.validate_query",
                name="Validate Raw Log Query Syntax",
                description="Validates raw log search query syntax against Chronicle query compiler.",
                category="log",
                handler=self.validate_raw_log_query,
                mcp_tool_name="validate_raw_log_query",
                composed=False,
                evidence_path="evidence/log/validate_query",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="log.raw_logs.search",
                name="Search Raw Logs",
                description="Searches unparsed or unnormalized raw log records matching queries, log types, and time ranges.",
                category="log",
                handler=self.search_raw_logs,
                mcp_tool_name="search_raw_logs",
                composed=False,
                evidence_path="evidence/log/raw_logs_search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="event.investigate",
                name="Event Deep Investigation",
                description="Retrieves canonical UDM fields and raw log payload with complete provenance.",
                category="event",
                handler=self.investigate_event,
                mcp_tool_name="investigate_event",
                composed=True,
                evidence_path="evidence/event/investigate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.refine",
                name="Filter-Based Search Refinement",
                description="Refines existing queries by applying structured inclusion/exclusion filters on UDM paths.",
                category="search",
                handler=self.refine_search,
                mcp_tool_name="refine_search",
                composed=True,
                uses=("search.udm",),
                evidence_path="evidence/search/refine",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="search.from_entity",
                name="Entity Contextual Pivot Search",
                description="Translates high-level entity artifacts into canonical UDM query expressions.",
                category="search",
                handler=self.search_from_entity,
                mcp_tool_name="search_from_entity",
                composed=True,
                uses=("search.udm",),
                evidence_path="evidence/search/from_entity",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="entity.search_udm",
                name="UDM Entity Graph Search",
                description="Executes streaming searches across the native UDM entity graph (graph.entity.*).",
                category="entity",
                handler=self.search_entity_graph,
                mcp_tool_name="search_entity_udm",
                composed=True,
                uses=("search.udm",),
                evidence_path="evidence/entity/search_udm",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="ioc.search_enterprise",
                name="Enterprise-Wide IoC Intelligence Search",
                description="Searches enterprise IoC matches and Mandiant breach intelligence for indicators.",
                category="ioc",
                handler=self.search_enterprise_iocs,
                mcp_tool_name="search_enterprise_iocs",
                composed=False,
                cardinality="bounded",
                evidence_path="evidence/ioc/search_enterprise",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="entity.summarize",
                name="Entity Summarization Profile",
                description="Retrieves entity timeline intervals, prevalence metrics, and metadata.",
                category="entity",
                handler=self.summarize_entity,
                mcp_tool_name="summarize_entity",
                composed=False,
                cardinality="single",
                evidence_path="evidence/entity/summarize",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="entity.investigate",
                name="Unified Cross-Engine Entity Investigation",
                description="Correlates an indicator across UDM Entity Graph, UDM Events, Enterprise IoC Intelligence, and SOAR Cases.",
                category="entity",
                handler=self.investigate_entity,
                mcp_tool_name="investigate_entity",
                composed=True,
                uses=("entity.search_udm", "search.from_entity", "ioc.search_enterprise", "case.search", "entity.summarize"),
                evidence_path="evidence/entity/investigate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.investigate",
                name="SOAR Case Workspace Deep Investigation",
                description="Aggregates case metadata, security alerts, involved entities, and analyst comments.",
                category="case",
                handler=self.investigate_case,
                mcp_tool_name="investigate_case",
                composed=True,
                evidence_path="evidence/case/investigate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.comment",
                name="Add Case Comment Record",
                description="Adds structured analyst investigation comments to a SOAR case.",
                category="case",
                handler=self.add_case_comment,
                mcp_tool_name="add_case_comment",
                composed=False,
                evidence_path="evidence/case/comment",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.list_comments",
                name="List SOAR Case Comments",
                description="Lists all analyst comments and AI assessment notes for a SOAR case.",
                category="case",
                handler=self.list_case_comments,
                mcp_tool_name="list_case_comments",
                composed=False,
                evidence_path="evidence/case/comments",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.get_wall",
                name="Get SOAR Case Activity Wall",
                description="Retrieves the complete SOAR case activity stream including status changes, tag updates, and playbook execution steps.",
                category="case",
                handler=self.get_case_wall,
                mcp_tool_name="get_case_wall",
                composed=False,
                evidence_path="evidence/case/wall",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.update",
                name="Update SOAR Case Properties",
                description="Mutates case attributes such as assignee, stage, incident flag, or priority.",
                category="case",
                handler=self.update_case,
                mcp_tool_name="update_case",
                composed=False,
                evidence_path="evidence/case/update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.assign",
                name="Assign SOAR Case",
                description="Assigns a SOAR case to a SOC role (@Role) or user GUID.",
                category="case",
                handler=self.assign_case,
                mcp_tool_name="assign_case",
                composed=False,
                evidence_path="evidence/case/assign",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.set_stage",
                name="Set SOAR Case Stage",
                description="Updates the lifecycle stage of a SOAR case.",
                category="case",
                handler=self.set_case_stage,
                mcp_tool_name="set_case_stage",
                composed=False,
                evidence_path="evidence/case/set_stage",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.set_incident",
                name="Set SOAR Case Incident Status",
                description="Marks or unmarks a SOAR case as an incident.",
                category="case",
                handler=self.set_case_incident,
                mcp_tool_name="set_case_incident",
                composed=False,
                evidence_path="evidence/case/set_incident",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.evidence.attach",
                name="Attach Evidence to Case",
                description="Batch attaches evidence items (detections, events, alerts) to a Google SecOps case.",
                category="case",
                handler=self.attach_case_evidence,
                mcp_tool_name="attach_case_evidence",
                composed=False,
                evidence_path="evidence/case/evidence/attach",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.evidence.detach",
                name="Detach Evidence from Case",
                description="Batch detaches evidence items from a Google SecOps case.",
                category="case",
                handler=self.detach_case_evidence,
                mcp_tool_name="detach_case_evidence",
                composed=False,
                evidence_path="evidence/case/evidence/detach",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.detection.correlate",
                name="Correlate Silent Detections to Case",
                description="Pivots across all entities involved in a case, searches UDM for non-alerting detections or matching events, and attaches them as case evidence.",
                category="case",
                handler=self.correlate_silent_detections,
                mcp_tool_name="correlate_silent_detections",
                composed=True,
                uses=("case.investigate", "search.udm", "case.evidence.attach", "case.comment"),
                evidence_path="evidence/case/detection/correlate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_alert.update",
                name="Update Case Alert",
                description="Mutates case alert attributes such as priority or status.",
                category="case",
                handler=self.update_case_alert,
                mcp_tool_name="update_case_alert",
                composed=False,
                evidence_path="evidence/case/alert_update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_alert.set_priority",
                name="Set Case Alert Priority",
                description="Updates the priority level of a specific case alert.",
                category="case",
                handler=self.set_case_alert_priority,
                mcp_tool_name="set_case_alert_priority",
                composed=False,
                evidence_path="evidence/case/alert_set_priority",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_alert.create_recommendation",
                name="Create Case Alert Recommendation",
                description="Initiates asynchronous generation of a Gemini AI recommendation for a case alert.",
                category="case",
                handler=self.create_case_alert_recommendation,
                mcp_tool_name="create_case_alert_recommendation",
                composed=False,
                evidence_path="evidence/case/alert_create_recommendation",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_alert.fetch_recommendation",
                name="Fetch Case Alert Recommendation",
                description="Fetches a previously generated Gemini AI recommendation for a case alert by recommendation ID.",
                category="case",
                handler=self.fetch_case_alert_recommendation,
                mcp_tool_name="fetch_case_alert_recommendation",
                composed=False,
                evidence_path="evidence/case/alert_fetch_recommendation",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_alert.get_recommendation",
                name="Get Case Alert Recommendation",
                description="End-to-end workflow to trigger Gemini AI recommendation generation and poll until completion or failure.",
                category="case",
                handler=self.get_case_alert_recommendation,
                mcp_tool_name="get_case_alert_recommendation",
                composed=True,
                uses=("case_alert.create_recommendation", "case_alert.fetch_recommendation"),
                evidence_path="evidence/case/alert_get_recommendation",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.get_or_create_summary",
                name="Get or Create SOAR Case AI Summary",
                description="Gets or initiates generation of a Gemini AI-driven overview, reasons, and next steps for a SOAR case.",
                category="case",
                handler=self.get_or_create_case_summary,
                mcp_tool_name="get_or_create_case_summary",
                composed=False,
                evidence_path="evidence/case/get_or_create_summary",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.get_summary",
                name="Get SOAR Case AI Summary (Polled)",
                description="Requests Gemini AI case summary and polls until generation is complete or timeout.",
                category="case",
                handler=self.get_case_summary,
                mcp_tool_name="get_case_summary",
                composed=True,
                uses=("case.get_or_create_summary",),
                evidence_path="evidence/case/get_summary",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.remediation_plan.list",
                name="List Case Remediation Plans",
                description="Lists AI-generated agentic response / remediation plans for cases and alerts.",
                category="case",
                handler=self.list_remediation_plans,
                mcp_tool_name="list_remediation_plans",
                composed=False,
                evidence_path="evidence/case/remediation_plan_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.remediation_plan.get",
                name="Get Case Remediation Plan",
                description="Fetches a specific AI-generated agentic response / remediation plan by plan ID or resource name.",
                category="case",
                handler=self.get_remediation_plan,
                mcp_tool_name="get_remediation_plan",
                composed=False,
                evidence_path="evidence/case/remediation_plan_get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.agentic_response_plan.get",
                name="Get Agentic Response Plan",
                description="Resolves an AI-driven agentic response plan by either case ID or plan ID.",
                category="case",
                handler=self.get_agentic_response_plan,
                mcp_tool_name="get_agentic_response_plan",
                composed=True,
                uses=("case.remediation_plan.list", "case.remediation_plan.get"),
                evidence_path="evidence/case/remediation_plan_get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="investigation.tina.list",
                name="List Gemini TINA Investigations",
                description="Lists and paginates autonomous Gemini Triage & Investigation Agent (TINA) investigations with verdicts and metadata.",
                category="investigation",
                handler=self.list_tina_investigations,
                mcp_tool_name="list_tina_investigations",
                evidence_path="evidence/investigation/tina_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="investigation.tina.get",
                name="Get Gemini TINA Investigation",
                description="Retrieves a complete Gemini TINA investigation report including verdict, summary, confidence, and all executed reasoning and search steps.",
                category="investigation",
                handler=self.get_tina_investigation,
                mcp_tool_name="get_tina_investigation",
                evidence_path="evidence/investigation/tina_get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="alert.tina.latest",
                name="Get Latest Gemini TINA Investigation for Alert",
                description="Retrieves the most recent Gemini TINA investigation associated with a specific alert ID.",
                category="investigation",
                handler=self.get_alert_latest_tina_investigation,
                mcp_tool_name="get_alert_latest_tina_investigation",
                evidence_path="evidence/investigation/tina_alert_latest",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="alert.investigate",
                name="SOAR Security Alert Deep Investigation",
                description="Retrieves security alert details with root-cause entities and raw log attachments.",
                category="alert",
                handler=self.investigate_alert,
                mcp_tool_name="investigate_alert",
                composed=True,
                evidence_path="evidence/alert/investigate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.search",
                name="SOAR Case Search & Multi-Facet Filtering",
                description="Searches, lists, and filters SOAR cases across time ranges, status, priority, and stages.",
                category="case",
                handler=self.search_cases,
                mcp_tool_name="search_cases",
                composed=False,
                evidence_path="evidence/case/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.list",
                name="SOAR Case Listing (Exact Status Filter)",
                description="Lists SOAR cases from the native cases collection with exact open/closed status, environment, priority, stage, assignee, important and incident filters, no time window, paginated up to a caller bound.",
                category="case",
                handler=self.list_cases,
                mcp_tool_name="list_cases",
                composed=False,
                evidence_path="discovery/observations/04_case_list_native_collection.md",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.orchestrate_triage",
                name="Orchestrate Case Triage",
                description="Batched retrieval, parallel investigation, and automated initial triage assessment for SOAR cases.",
                category="case",
                handler=self.orchestrate_case_triage,
                mcp_tool_name="orchestrate_case_triage",
                composed=True,
                uses=("case.search", "case.investigate", "case.get_summary"),
                evidence_path="discovery/observations/03_case_triage_first_touch.md",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.triage",
                name="Triage Single Case",
                description="End-to-end single case triage: deep investigation, Gemini AI summary, title and entity precedent correlation, novelty assessment, and stage transitions.",
                category="case",
                handler=self.triage_case,
                mcp_tool_name="triage_case",
                composed=True,
                uses=("case.investigate", "case.get_summary", "case.search"),
                evidence_path="discovery/observations/03_case_triage_first_touch.md",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.timeline",
                name="Get Case Chronological Timeline",
                description="Synthesizes a chronologically ordered event timeline across Case Creation, Alert Detections, Playbook Milestones, Analyst Comments, and Case Updates.",
                category="case",
                handler=self.get_case_timeline,
                mcp_tool_name="get_case_timeline",
                composed=True,
                uses=("case.investigate",),
                evidence_path="discovery/observations/03_case_triage_first_touch.md",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case.ai_investigate",
                name="Autonomous AI Case Investigation",
                description="Executes deep AI-driven case investigation: fetches AI summary, extracts network and user indicators, runs automated UDM searches across Chronicle event logs, and assesses enterprise impact.",
                category="case",
                handler=self.ai_investigate_case,
                mcp_tool_name="ai_investigate_case",
                composed=True,
                uses=("case.investigate", "case.get_summary", "search.udm", "case.comment"),
                evidence_path="discovery/observations/03_case_triage_first_touch.md",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.search",
                name="SOAR Playbook Search & Discovery",
                description="Searches, lists, and filters SOAR playbooks across categories, triggers, and environments.",
                category="playbook",
                handler=self.search_playbooks,
                mcp_tool_name="search_playbooks",
                composed=False,
                evidence_path="evidence/playbook/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.get",
                name="SOAR Playbook Deep Inspection",
                description="Retrieves complete playbook definition, trigger conditions, and step execution DAG.",
                category="playbook",
                handler=self.get_playbook,
                mcp_tool_name="get_playbook",
                composed=False,
                evidence_path="evidence/playbook/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.categories",
                name="List Playbook Categories",
                description="Lists all SOAR Playbook folder categories.",
                category="playbook",
                handler=self.list_playbook_categories,
                mcp_tool_name="list_playbook_categories",
                composed=False,
                evidence_path="evidence/playbook/categories",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.save",
                name="Save SOAR Playbook Definition",
                description="Creates or updates a SOAR playbook or block workflow definition with automatic category ID/name synchronization.",
                category="playbook",
                handler=self.save_playbook,
                mcp_tool_name="save_playbook",
                composed=False,
                side_effects=["write_playbook"],
                evidence_path="evidence/playbook/save",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.update_widget",
                name="Update SOAR Playbook HTML Widget",
                description="Updates an embedded HTML widget inside a SOAR Playbook's ViewsTemplates and saves the playbook.",
                category="playbook",
                handler=self.update_playbook_widget,
                mcp_tool_name="update_playbook_widget",
                composed=True,
                uses=("playbook.get", "playbook.save"),
                side_effects=["write_playbook"],
                evidence_path="evidence/playbook/update_widget",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.delete",
                name="Delete SOAR Playbooks",
                description="Deletes one or more SOAR playbooks by UUID identifier, numeric ID, or name.",
                category="playbook",
                handler=self.delete_playbooks,
                mcp_tool_name="delete_playbooks",
                composed=False,
                side_effects=["delete_playbook"],
                evidence_path="evidence/playbook/delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.instances",
                name="Alert Playbook Run Instances",
                description="Retrieves authoritative per-alert playbook run instances and the executed step DAG.",
                category="playbook",
                handler=self.get_alert_playbook_instances,
                mcp_tool_name="get_alert_playbook_instances",
                composed=False,
                evidence_path="evidence/playbook/instances",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.audit_health",
                name="SOAR Playbook Health & Telemetry Audit",
                description="Audits SOAR playbooks and modular blocks for configuration hygiene, failure spikes, faulted actions, and queue latency using native Playbook Dashboard analytics.",
                category="playbook",
                handler=self.audit_soar_playbook_health,
                mcp_tool_name="audit_soar_playbook_health",
                composed=True,
                uses=("playbook.search", "dashboard.execute_query"),
                evidence_path="evidence/playbook/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="playbook.decay_audit",
                name="SOAR Playbook Inventory & Decay Audit",
                description="Audits SOAR playbooks and modular nested blocks for 100-pt static resilience, 30-day execution telemetry, Mermaid DAG synthesis, and Firestore persistence.",
                category="playbook",
                handler=self.audit_playbook_decay,
                mcp_tool_name="audit_playbook_decay",
                composed=True,
                uses=("playbook.search", "playbook.get", "dashboard.execute_query"),
                evidence_path="evidence/playbook/decay_audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.search",
                name="SOAR Integration Search & Discovery",
                description="Searches, lists, and filters SOAR integrations across environments, status, and certification.",
                category="integration",
                handler=self.search_integrations,
                mcp_tool_name="search_integrations",
                composed=False,
                evidence_path="evidence/integration/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.get",
                name="SOAR Integration Deep Inspection",
                description="Retrieves complete integration details, instances, remote agents, and documentation.",
                category="integration",
                handler=self.get_integration,
                mcp_tool_name="get_integration",
                composed=False,
                evidence_path="evidence/integration/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.instances",
                name="List Integration Instances",
                description="Lists configured integration instances across environments or specific integrations.",
                category="integration",
                handler=self.list_integration_instances,
                mcp_tool_name="list_integration_instances",
                composed=False,
                evidence_path="evidence/integration/instances",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.instance.affected_items",
                name="SOAR Integration Instance Affected Items",
                description="Resolves affected playbooks and downstream items before instance deletion.",
                category="integration",
                handler=self.get_integration_instance_affected_items,
                mcp_tool_name="get_integration_instance_affected_items",
                composed=False,
                evidence_path="evidence/integration/instance_affected_items",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.instance.delete",
                name="Delete SOAR Integration Instance",
                description="Deletes a configured integration instance with pre-flight dependency guard.",
                category="integration",
                handler=self.delete_integration_instance,
                mcp_tool_name="delete_integration_instance",
                composed=True,
                uses=("integration.instance.affected_items",),
                evidence_path="evidence/integration/instance_delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="integration.remote_agents",
                name="List Remote Execution Agents",
                description="Lists remote proxy execution agents and their supported environments.",
                category="integration",
                handler=self.list_remote_agents,
                mcp_tool_name="list_remote_agents",
                composed=False,
                evidence_path="evidence/integration/remote_agents",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.search",
                name="SOAR Scheduled Jobs Discovery",
                description="Searches, lists, and filters SOAR scheduled jobs across integrations and execution schedules.",
                category="job",
                handler=self.search_jobs,
                mcp_tool_name="search_jobs",
                composed=False,
                evidence_path="evidence/job/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.get",
                name="SOAR Scheduled Job Deep Inspection",
                description="Retrieves complete job details, deployed runtime instances, and recent execution logs.",
                category="job",
                handler=self.get_job,
                mcp_tool_name="get_job",
                composed=False,
                evidence_path="evidence/job/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.instances",
                name="List Job Instances",
                description="Lists runtime job instances deployed across environments or specific jobs.",
                category="job",
                handler=self.list_job_instances,
                mcp_tool_name="list_job_instances",
                composed=False,
                evidence_path="evidence/job/instances",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.logs",
                name="Get Job Instance Execution Logs",
                description="Retrieves execution run records and output logs for a job instance.",
                category="job",
                handler=self.get_job_instance_logs,
                mcp_tool_name="get_job_instance_logs",
                composed=False,
                evidence_path="evidence/job/logs",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.update",
                name="Update SOAR Scheduled Job",
                description="Updates a SOAR scheduled job definition (script, description, enabled, parameters) and optionally syncs script changes to its active job instances.",
                category="job",
                handler=self.update_job,
                mcp_tool_name="update_job",
                composed=False,
                side_effects=["write_job"],
                evidence_path="evidence/job/update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.instance.update",
                name="Update SOAR Job Instance",
                description="Updates a configured runtime SOAR job instance (script, schedule, parameters, or enabled status).",
                category="job",
                handler=self.update_job_instance,
                mcp_tool_name="update_job_instance",
                composed=False,
                side_effects=["write_job_instance"],
                evidence_path="evidence/job/instance_update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="job.instance.create",
                name="Create SOAR Job Instance",
                description="Creates a new scheduled runtime SOAR job instance under a job definition.",
                category="job",
                handler=self.create_job_instance,
                mcp_tool_name="create_job_instance",
                composed=False,
                side_effects=["create_job_instance"],
                evidence_path="evidence/job/instance_create",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="content_pack.search",
                name="Content Hub Content Packs Discovery",
                description="Searches, lists, and filters Content Hub Marketplace Content Packs across categories and pack types.",
                category="content_pack",
                handler=self.search_content_packs,
                mcp_tool_name="search_content_packs",
                composed=False,
                evidence_path="evidence/content_pack/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="content_pack.get",
                name="Content Hub Content Pack Deep Inspection",
                description="Retrieves complete Content Pack details and bundled playbooks, integrations, dashboards, rulesets, and queries.",
                category="content_pack",
                handler=self.get_content_pack,
                mcp_tool_name="get_content_pack",
                composed=False,
                evidence_path="evidence/content_pack/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="content_pack.categories",
                name="Content Hub Categories Taxonomy",
                description="Discovers and aggregates the taxonomy of Content Hub categories with pack counts.",
                category="content_pack",
                handler=self.list_content_pack_categories,
                mcp_tool_name="list_content_pack_categories",
                composed=False,
                evidence_path="evidence/content_pack/categories",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.search_rulesets",
                name="Search Curated Rule Sets",
                description="Discovers and searches Google SecOps Curated Rule Sets with MITRE ATT&CK mappings and log sources.",
                category="curated_detections",
                handler=self.search_curated_rulesets,
                mcp_tool_name="search_curated_rulesets",
                composed=False,
                evidence_path="evidence/curated_detections/rulesets",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.deployments.list",
                name="List Curated Rule Set Deployments",
                description="Lists every curated rule set BROAD/PRECISE deployment (enabled, alerting) in one bulk call, optionally joined with rule set display names.",
                category="curated_detections",
                handler=self.list_curated_rule_set_deployments,
                mcp_tool_name="list_curated_rule_set_deployments",
                composed=False,
                evidence_path="evidence/curated_detections/deployments_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.rulesets.list",
                name="List Curated Rule Sets",
                description="Lists Curated Rule Sets with page-token pagination (all_pages / max_results).",
                category="curated_detections",
                handler=self.list_curated_rulesets,
                mcp_tool_name="list_curated_rulesets",
                composed=False,
                evidence_path="evidence/curated_detections/rulesets_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.rules.list",
                name="List Curated Rules",
                description="Lists individual Google-curated rules with page-token pagination (slow endpoint; cache results).",
                category="curated_detections",
                handler=self.list_curated_rules,
                mcp_tool_name="list_curated_rules",
                composed=False,
                evidence_path="evidence/curated_detections/rules_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.get_ruleset",
                name="Curated Rule Set Deep Inspection",
                description="Deep-inspects a Curated Rule Set, its broad/precise deployments, member rules, and detection telemetry.",
                category="curated_detections",
                handler=self.get_curated_ruleset,
                mcp_tool_name="get_curated_ruleset",
                composed=False,
                evidence_path="evidence/curated_detections/ruleset_get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.get_rule",
                name="Curated Rule YARA-L Inspection",
                description="Retrieves an individual Curated Rule, its MITRE techniques, false positives, and raw YARA-L logic.",
                category="curated_detections",
                handler=self.get_curated_rule,
                mcp_tool_name="get_curated_rule",
                composed=False,
                evidence_path="evidence/curated_detections/rule_get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.metrics",
                name="Curated Detection Metrics & Quotas",
                description="Aggregates detection firing counts and retrieves tenant-wide rule quotas and telemetry.",
                category="curated_detections",
                handler=self.get_curated_detection_metrics,
                mcp_tool_name="get_curated_detection_metrics",
                composed=False,
                evidence_path="evidence/curated_detections/metrics",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.set_deployment",
                name="Set Curated Rule Set Deployment",
                description="Updates enabled and alerting states for a Curated Rule Set precision deployment.",
                category="curated_detections",
                handler=self.set_curated_ruleset_deployment,
                mcp_tool_name="set_curated_ruleset_deployment",
                composed=False,
                evidence_path="evidence/curated_detections/deployment_set",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.audit_health",
                name="Curated Detections Health & Hygiene Audit",
                description="Performs a comprehensive deployment posture audit, detects misconfigurations like broad alerting, identifies top firing rules, and ranks newest/oldest content.",
                category="curated_detections",
                handler=self.audit_curated_detections_health,
                mcp_tool_name="audit_curated_detections_health",
                composed=True,
                uses=(
                    "curated_detections.search_rulesets",
                    "curated_detections.get_ruleset",
                    "curated_detections.metrics",
                ),
                evidence_path="evidence/curated_detections/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.refinements.list",
                name="List UDM Findings Refinements",
                description="Lists active UDM findings refinements and detection exclusions across the tenant.",
                category="curated_detections",
                handler=self.list_findings_refinements,
                mcp_tool_name="list_findings_refinements",
                composed=False,
                evidence_path="evidence/curated_detections/refinements_list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.refinements.test",
                name="Test UDM Findings Refinement",
                description="Simulates and dry-runs an exclusion query against historical detections to compute noise suppression ratio.",
                category="curated_detections",
                handler=self.test_findings_refinement,
                mcp_tool_name="test_findings_refinement",
                composed=False,
                evidence_path="evidence/curated_detections/refinements_test",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.refinements.create",
                name="Create UDM Findings Refinement",
                description="Creates a new UDM findings refinement exclusion for curated rules or tenant-wide detections.",
                category="curated_detections",
                handler=self.create_findings_refinement,
                mcp_tool_name="create_findings_refinement",
                composed=False,
                evidence_path="evidence/curated_detections/refinements_create",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.refinements.delete",
                name="Delete UDM Findings Refinement",
                description="Removes an active UDM findings refinement exclusion.",
                category="curated_detections",
                handler=self.delete_findings_refinement,
                mcp_tool_name="delete_findings_refinement",
                composed=False,
                evidence_path="evidence/curated_detections/refinements_delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.top_noisy_rules",
                name="Identify Top Noisy Rules",
                description="Aggregates and ranks top firing detection rules with alert state, volume, and Google vs Customer rule classification.",
                category="curated_detections",
                handler=self.find_top_noisy_rules,
                mcp_tool_name="find_top_noisy_rules",
                composed=False,
                evidence_path="evidence/curated_detections/tuning_top_noisy",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.entity_cardinality",
                name="Analyze Entity Cardinality",
                description="Profiles multi-dimensional entity subfield distributions (IPs, hostnames, users, processes, DNS) for a detection rule.",
                category="curated_detections",
                handler=self.analyze_entity_cardinality,
                mcp_tool_name="analyze_entity_cardinality",
                composed=False,
                evidence_path="evidence/curated_detections/tuning_entity_cardinality",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.case_history",
                name="Cross-Reference Rule Cases",
                description="Cross-references historical SOAR cases associated with a detection rule to extract analyst resolutions and root causes.",
                category="curated_detections",
                handler=self.cross_reference_rule_cases,
                mcp_tool_name="cross_reference_rule_cases",
                composed=False,
                evidence_path="evidence/curated_detections/tuning_case_history",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.case_environments",
                name="Rule to SOAR Environment Join",
                description="Counts distinct SOAR cases per (detection rule_id, case.environment) over a lookback window in one dashboard query.",
                category="rule",
                handler=self.get_rule_case_environments,
                mcp_tool_name="get_rule_case_environments",
                composed=False,
                # Explicit: "case_environments" is not a known read verb. The
                # result is one aggregated dashboard query with a fixed row
                # limit, so it is bounded (same as rule.decay.telemetry).
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/rule/case_environments",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.diagnose",
                name="Diagnose and Tune Detection",
                description="End-to-end autonomous workflow that analyzes noisy rules, profiles cardinality, cross-references SOAR cases, formulates exclusions, and dry-run tests suppression.",
                category="curated_detections",
                handler=self.tune_detection,
                mcp_tool_name="tune_detection",
                composed=True,
                uses=(
                    "curated_detections.tuning.entity_cardinality",
                    "curated_detections.tuning.case_history",
                    "curated_detections.refinements.test",
                    "curated_detections.get_rule",
                    "rule.get",
                ),
                evidence_path="evidence/curated_detections/tuning_diagnose",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.samples",
                name="Sample Correlated Detection Events",
                description="Pulls correlated multi-attribute detection tuples (user + command + host + IP) from detection collection elements.",
                category="curated_detections",
                handler=self.sample_detection_events,
                mcp_tool_name="sample_detection_events",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/curated_detections/tuning_samples",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="curated_detections.tuning.synthesize",
                name="Synthesize Detection Tuning",
                description="Synthesizes safe multi-factor exclusions enforcing HITL safety guardrails, compiles candidate rule patches or UDM refinements, and calculates noise reduction projections.",
                category="curated_detections",
                handler=self.synthesize_detection_tuning,
                mcp_tool_name="synthesize_detection_tuning",
                composed=True,
                uses=[
                    "curated_detections.tuning.entity_cardinality",
                    "curated_detections.tuning.samples",
                    "curated_detections.refinements.test",
                    "curated_detections.get_rule",
                    "rule.get",
                    "rule.verify",
                ],
                evidence_path="evidence/curated_detections/tuning_synthesize",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="marketplace_integration.search",
                name="Search Marketplace Response Integrations",
                description="Discovers, searches, and filters Marketplace Response Integrations across categories and update states.",
                category="marketplace_integration",
                handler=self.search_marketplace_integrations,
                mcp_tool_name="search_marketplace_integrations",
                composed=False,
                evidence_path="evidence/marketplace_integration/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="marketplace_integration.get",
                name="Marketplace Response Integration Deep Inspection",
                description="Retrieves complete integration composite, actions, connectors, jobs, managers, and release notes.",
                category="marketplace_integration",
                handler=self.get_marketplace_integration,
                mcp_tool_name="get_marketplace_integration",
                composed=False,
                evidence_path="evidence/marketplace_integration/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="marketplace_integration.diff",
                name="Marketplace Commercial Version Diff",
                description="Compares commercial upgrade differences and overrides between installed and target versions.",
                category="marketplace_integration",
                handler=self.get_marketplace_integration_diff,
                mcp_tool_name="get_marketplace_integration_diff",
                composed=False,
                evidence_path="evidence/marketplace_integration/diff",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="marketplace_integration.affected_items",
                name="Marketplace Downstream Affected Items",
                description="Resolves affected environment instances and active playbooks before integration modifications.",
                category="marketplace_integration",
                handler=self.get_marketplace_integration_affected_items,
                mcp_tool_name="get_marketplace_integration_affected_items",
                composed=False,
                evidence_path="evidence/marketplace_integration/affected_items",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.search",
                name="Google SecOps Native Dashboards Discovery",
                description="Searches, lists, and filters native dashboards configured in Google SecOps.",
                category="dashboard",
                handler=self.search_dashboards,
                mcp_tool_name="search_dashboards",
                composed=False,
                evidence_path="evidence/dashboard/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.get",
                name="Google SecOps Dashboard Deep Inspection",
                description="Retrieves complete composite dashboard graph with layout, batch-resolved charts, and queries.",
                category="dashboard",
                handler=self.get_dashboard,
                mcp_tool_name="get_dashboard",
                composed=True,
                evidence_path="evidence/dashboard/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.create",
                name="Create Google SecOps Native Dashboard",
                description="Creates a new Native Dashboard in Google SecOps.",
                category="dashboard",
                handler=self.create_dashboard,
                mcp_tool_name="create_dashboard",
                composed=False,
                side_effects=["create_dashboard"],
                evidence_path="evidence/dashboard/create",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.update",
                name="Update Google SecOps Native Dashboard",
                description="Updates an existing Native Dashboard's display name, description, filters, or chart layouts.",
                category="dashboard",
                handler=self.update_dashboard,
                mcp_tool_name="update_dashboard",
                composed=False,
                side_effects=["write_dashboard"],
                evidence_path="evidence/dashboard/update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.delete",
                name="Delete Google SecOps Native Dashboard",
                description="Deletes a Native Dashboard by ID.",
                category="dashboard",
                handler=self.delete_dashboard,
                mcp_tool_name="delete_dashboard",
                composed=False,
                side_effects=["delete_dashboard"],
                evidence_path="evidence/dashboard/delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.duplicate",
                name="Duplicate Google SecOps Native Dashboard",
                description="Duplicates an existing Native Dashboard under a new display name.",
                category="dashboard",
                handler=self.duplicate_dashboard,
                mcp_tool_name="duplicate_dashboard",
                composed=False,
                side_effects=["create_dashboard"],
                evidence_path="evidence/dashboard/duplicate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.chart.add",
                name="Add Chart to Google SecOps Native Dashboard",
                description="Adds a chart widget (visualization, markdown, or button) and optional query to a Native Dashboard.",
                category="dashboard",
                handler=self.add_dashboard_chart,
                mcp_tool_name="add_dashboard_chart",
                composed=False,
                side_effects=["write_dashboard"],
                evidence_path="evidence/dashboard/chart_add",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.chart.update",
                name="Update Chart/Query on Google SecOps Native Dashboard",
                description="Updates an existing DashboardChart and/or its associated DashboardQuery.",
                category="dashboard",
                handler=self.update_dashboard_chart,
                mcp_tool_name="update_dashboard_chart",
                composed=False,
                side_effects=["write_dashboard"],
                evidence_path="evidence/dashboard/chart_update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.chart.remove",
                name="Remove Chart from Google SecOps Native Dashboard",
                description="Removes a chart from a Native Dashboard.",
                category="dashboard",
                handler=self.remove_dashboard_chart,
                mcp_tool_name="remove_dashboard_chart",
                composed=False,
                side_effects=["write_dashboard"],
                evidence_path="evidence/dashboard/chart_remove",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.execute_query",
                name="Google SecOps Dashboard Query Execution",
                description="Executes a dashboard widget query against live telemetry and transforms columnar results into tabular records.",
                category="dashboard",
                handler=self.execute_dashboard_query,
                mcp_tool_name="execute_dashboard_query",
                composed=False,
                evidence_path="evidence/dashboard/execute_query",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.validate_query",
                name="Google SecOps Dashboard Query Validation",
                description="Validates statistical / dashboard widget query syntax against the live Google SecOps query compiler.",
                category="dashboard",
                handler=self.validate_dashboard_query,
                mcp_tool_name="validate_dashboard_query",
                composed=False,
                evidence_path="evidence/dashboard/validate_query",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.health_check",
                name="Dashboard Health Check Execution",
                description="Executes comprehensive health check for a named dashboard by resolving configuration, executing all widget queries, and generating operational ingestion health summary.",
                category="dashboard",
                handler=self.run_dashboard_health_check,
                mcp_tool_name="run_dashboard_health_check",
                composed=True,
                uses=("dashboard.search", "dashboard.get", "dashboard.execute_query"),
                evidence_path="evidence/dashboard/health_check",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="dashboard.audit_health",
                name="Audit Dashboard Health & Governance",
                description="Audits native dashboards for recent creations, modifications, broken widget queries, empty placeholders, and staleness.",
                category="dashboard",
                handler=self.audit_dashboard_health,
                mcp_tool_name="audit_dashboard_health",
                composed=True,
                uses=("dashboard.search", "dashboard.get", "dashboard.validate_query"),
                evidence_path="evidence/dashboard/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="siem.managed_domains.get",
                name="Get Managed Email Domains Settings",
                description="Retrieves approved email domains for report deliveries and alerts.",
                category="siem_settings",
                handler=self.get_managed_domain_settings,
                mcp_tool_name="get_managed_domain_settings",
                composed=False,
                evidence_path="evidence/siem_settings/managed_domains",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed.search",
                name="Search Ingestion Feeds",
                description="Searches, lists, and filters push/pull ingestion feeds across source types and log types.",
                category="feed",
                handler=self.search_feeds,
                mcp_tool_name="search_feeds",
                composed=False,
                evidence_path="evidence/feed/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed.get",
                name="Feed Deep Inspection",
                description="Retrieves full configuration details and source parameters for an ingestion feed.",
                category="feed",
                handler=self.get_feed,
                mcp_tool_name="get_feed",
                composed=False,
                evidence_path="evidence/feed/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed.audit_health",
                name="Audit Ingestion Feed Health",
                description="Audits and correlates ingestion feed states, Health Hub telemetry, and transport latency.",
                category="feed",
                handler=self.audit_feed_health,
                mcp_tool_name="audit_feed_health",
                composed=True,
                uses=("feed.search", "dashboard.execute_query"),
                evidence_path="evidence/feed/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed.timestamp_integrity_audit",
                name="Ingestion Timestamp Integrity & Clock Skew Audit",
                description="Audits log sources for ingestion latency bottlenecks (Δt ≫ 0) and NTP clock skews (Δt < 0), classifies state progression, and synthesizes executive brief.",
                category="feed",
                handler=self.audit_timestamp_integrity,
                mcp_tool_name="audit_timestamp_integrity",
                composed=True,
                uses=("dashboard.execute_query",),
                evidence_path="evidence/feed/timestamp_integrity",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed.get_timestamp_integrity",
                name="Get Latest Ingestion Timestamp Integrity Report",
                description="Retrieves latest stored timestamp integrity baseline and progression metrics from Evidence Fabric.",
                category="feed",
                handler=self.get_latest_timestamp_integrity,
                mcp_tool_name="get_latest_timestamp_integrity",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/feed/timestamp_integrity_latest",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="pipeline.search",
                name="Search Log Processing Pipelines",
                description="Discovers and lists Data Processing Pipelines with parser transforms and Bindplane SaaS links.",
                category="siem_settings",
                handler=self.search_log_processing_pipelines,
                mcp_tool_name="search_log_processing_pipelines",
                composed=False,
                evidence_path="evidence/siem_settings/pipelines/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="pipeline.get",
                name="Log Processing Pipeline Deep Inspection",
                description="Retrieves full transform statements and stream bindings for a Data Processing Pipeline.",
                category="siem_settings",
                handler=self.get_log_processing_pipeline,
                mcp_tool_name="get_log_processing_pipeline",
                composed=False,
                evidence_path="evidence/siem_settings/pipelines/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed_schema.list_sources",
                name="List Feed Source Type Schemas",
                description="Lists all supported feed source types and collection mechanisms.",
                category="feed",
                handler=self.list_feed_source_type_schemas,
                mcp_tool_name="list_feed_source_type_schemas",
                composed=False,
                evidence_path="evidence/feed/schemas/sources",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="feed_schema.list_log_types",
                name="List Feed Log Type Schemas",
                description="Lists log types supported by a specific feed source with lean payload handling.",
                category="feed",
                handler=self.list_feed_log_type_schemas,
                mcp_tool_name="list_feed_log_type_schemas",
                composed=False,
                evidence_path="evidence/feed/schemas/log_types",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.log_types.list",
                name="List Supported Log Types",
                description="Discovers and filters supported ingestion log types cataloged in Google SecOps.",
                category="parser",
                handler=self.list_log_types,
                mcp_tool_name="list_log_types",
                composed=False,
                evidence_path="evidence/parser/log_types",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.search",
                name="Search Ingestion Parsers",
                description="Discovers and filters parsers across log types with creator and state filters.",
                category="parser",
                handler=self.search_parsers,
                mcp_tool_name="search_parsers",
                composed=False,
                evidence_path="evidence/parser/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.get",
                name="Parser Deep Inspection",
                description="Retrieves complete parser metadata and decoded Logstash CBN filter code.",
                category="parser",
                handler=self.get_parser,
                mcp_tool_name="get_parser",
                composed=False,
                evidence_path="evidence/parser/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.run",
                name="Run Ingestion Parser",
                description="Executes a Logstash CBN parser configuration against a raw log string.",
                category="parser",
                handler=self.run_parser,
                mcp_tool_name="run_parser",
                composed=False,
                evidence_path="evidence/parser/run",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.diagnose_unparsed",
                name="Diagnose Unparsed Logs",
                description="Finds unparsed raw logs for a log type and runs them against the active parser to diagnose errors.",
                category="parser",
                handler=self.diagnose_unparsed_logs,
                mcp_tool_name="diagnose_unparsed_logs",
                composed=True,
                uses=(
                    "log.raw_logs.search",
                    "parser.log_types.list",
                    "parser.get",
                    "parser.run",
                ),
                evidence_path="evidence/parser/diagnose_unparsed",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.extensions.search",
                name="Search Parser Extensions",
                description="Discovers parser extensions and dynamic parsing configurations across log types.",
                category="parser",
                handler=self.search_parser_extensions,
                mcp_tool_name="search_parser_extensions",
                composed=False,
                evidence_path="evidence/parser/extensions/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.extensions.get",
                name="Parser Extension Deep Inspection",
                description="Retrieves full parser extension configuration, decoded snippet, and test log.",
                category="parser",
                handler=self.get_parser_extension,
                mcp_tool_name="get_parser_extension",
                composed=False,
                evidence_path="evidence/parser/extensions/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.log_type_setting.get",
                name="Get Parser Log Type Setting",
                description="Retrieves autonomous parsing settings and extraction type for a specific log type.",
                category="parser",
                handler=self.get_log_type_setting,
                mcp_tool_name="get_log_type_setting",
                composed=False,
                evidence_path="evidence/parser/settings",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="parser.audit_health",
                name="Audit SIEM Parser Health",
                description="Audits and correlates SIEM parser states, CBN version drift, extension conflicts, and Health Hub telemetry.",
                category="parser",
                handler=self.audit_parser_health,
                mcp_tool_name="audit_parser_health",
                composed=True,
                uses=("parser.search", "parser.extensions.search", "dashboard.execute_query"),
                evidence_path="evidence/parser/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="preview_feature.list",
                name="List Preview Features",
                description="Discovers customer preview feature flags, enablement states, retirement schedules, and docs.",
                category="preview_feature",
                handler=self.list_preview_features,
                mcp_tool_name="list_preview_features",
                composed=False,
                evidence_path="evidence/preview_feature/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="preview_feature.get",
                name="Get Preview Feature Deep Inspection",
                description="Retrieves specific preview feature configuration, documentation, and retirement dates.",
                category="preview_feature",
                handler=self.get_preview_feature,
                mcp_tool_name="get_preview_feature",
                composed=False,
                evidence_path="evidence/preview_feature/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_rbac.scope.search",
                name="Search Data Access Scopes",
                description="Discovers and filters Data Access RBAC Scopes and allow/deny label counts.",
                category="data_rbac",
                handler=self.search_data_access_scopes,
                mcp_tool_name="search_data_access_scopes",
                composed=False,
                evidence_path="evidence/data_rbac/scope/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_rbac.scope.get",
                name="Data Access Scope Deep Inspection",
                description="Retrieves deep configuration of a Data Access Scope including label attachments.",
                category="data_rbac",
                handler=self.get_data_access_scope,
                mcp_tool_name="get_data_access_scope",
                composed=False,
                evidence_path="evidence/data_rbac/scope/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_rbac.label.search",
                name="Search Data Access Labels",
                description="Discovers Data Access Labels and their associated UDM filter query definitions.",
                category="data_rbac",
                handler=self.search_data_access_labels,
                mcp_tool_name="search_data_access_labels",
                composed=False,
                evidence_path="evidence/data_rbac/label/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_rbac.label.get",
                name="Data Access Label Deep Inspection",
                description="Retrieves full configuration of a Data Access Label including UDM filter expression.",
                category="data_rbac",
                handler=self.get_data_access_label,
                mcp_tool_name="get_data_access_label",
                composed=False,
                evidence_path="evidence/data_rbac/label/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_rbac.environment.search",
                name="Search SOAR Environments and Scopes",
                description="Discovers SOAR multi-tenant environments and inspects their bound Data Access Scopes.",
                category="data_rbac",
                handler=self.search_environment_scopes,
                mcp_tool_name="search_environment_scopes",
                composed=False,
                evidence_path="evidence/data_rbac/environment/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="enrichment.combination.list",
                name="List Enrichment Combinations",
                description="Discovers available enrichment types, target log types, and enrichment sources.",
                category="enrichment",
                handler=self.list_enrichment_combinations,
                mcp_tool_name="list_enrichment_combinations",
                composed=False,
                evidence_path="evidence/enrichment/combination/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="enrichment.control.search",
                name="Search Deployed Enrichment Controls",
                description="Discovers and filters deployed enrichment controls that restrict entity enrichments.",
                category="enrichment",
                handler=self.search_enrichment_controls,
                mcp_tool_name="search_enrichment_controls",
                composed=False,
                evidence_path="evidence/enrichment/control/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="enrichment.control.get",
                name="Enrichment Control Deep Inspection",
                description="Retrieves full configuration and timing rules for a deployed enrichment control.",
                category="enrichment",
                handler=self.get_enrichment_control,
                mcp_tool_name="get_enrichment_control",
                composed=False,
                evidence_path="evidence/enrichment/control/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="siem.agent_settings.get",
                name="Get Gemini Triage & Investigation Agent Settings",
                description="Retrieves tenant configuration for automated triage, investigation filters, delays, and quotas.",
                category="siem_settings",
                handler=self.get_agent_settings,
                mcp_tool_name="get_agent_settings",
                composed=False,
                evidence_path="evidence/siem_settings/agent_settings/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="siem.risk_config.get",
                name="Get Entity Risk Scoring Configuration",
                description="Retrieves UEBA entity risk scoring defaults, detection/alert scores, and weighting coefficients.",
                category="siem_settings",
                handler=self.get_entity_risk_config,
                mcp_tool_name="get_entity_risk_config",
                composed=False,
                evidence_path="evidence/siem_settings/risk_config/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="siem.tenant.get",
                name="Get Tenant Instance Details",
                description="Retrieves root tenant instance details, active URLs, feature flags, and workforce pool providers.",
                category="siem_settings",
                handler=self.get_tenant_instance,
                mcp_tool_name="get_tenant_instance",
                composed=False,
                evidence_path="evidence/siem_settings/tenant/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="tenant.posture.audit",
                name="Audit Complete Tenant Configuration Posture",
                description="Audits tenant configuration posture across root instance, Gemini AI triage, UEBA risk scoring, pipelines, SOAR global settings, and SOC topography.",
                category="siem_settings",
                handler=self.audit_tenant_posture,
                mcp_tool_name="audit_tenant_posture",
                composed=True,
                uses=(
                    "siem.tenant.get",
                    "siem.agent_settings.get",
                    "siem.risk_config.get",
                    "siem.managed_domains.get",
                    "pipeline.search",
                    "soar.company.get",
                    "soar.data_retention.get",
                    "soar.email_settings.get",
                    "soar.support_settings.get",
                    "case_config.alert_grouping.settings.get",
                    "case_config.title_settings.get",
                    "soar.soc_role.list",
                    "soar.environment.search",
                    "soar.remote_agent.search",
                    "soar.network.search",
                    "soar.domain.search",
                    "soar.custom_list.search",
                ),
                evidence_path="evidence/tenant_settings/audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.user.search",
                name="Search SOAR Users",
                description="Discovers and filters SOAR users and external identity profiles.",
                category="soar_settings",
                handler=self.search_soar_users,
                mcp_tool_name="search_soar_users",
                composed=False,
                evidence_path="evidence/soar_settings/users/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.user.get",
                name="Get SOAR User Details",
                description="Retrieves deep profile details of a single SOAR user including roles, permission groups, and environment access.",
                category="soar_settings",
                handler=self.get_soar_user,
                mcp_tool_name="get_soar_user",
                composed=False,
                evidence_path="evidence/soar_settings/users/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.soc_role.list",
                name="List SOC Roles",
                description="Lists configured SOC roles and workflow assignment access hierarchy.",
                category="soar_settings",
                handler=self.list_soc_roles,
                mcp_tool_name="list_soc_roles",
                composed=False,
                evidence_path="evidence/soar_settings/soc_roles/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.company.get",
                name="Get Company Rebranding Settings",
                description="Retrieves tenant branding, report customizations, and system email settings.",
                category="soar_settings",
                handler=self.get_company_settings,
                mcp_tool_name="get_company_settings",
                composed=False,
                evidence_path="evidence/soar_settings/company/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.tag.search",
                name="Search Case Tag Definitions",
                description="Discovers and filters case tag classification rules and criteria.",
                category="case_config",
                handler=self.search_case_tag_definitions,
                mcp_tool_name="search_case_tag_definitions",
                composed=False,
                evidence_path="evidence/case_config/tags/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.stage.list",
                name="List Case Stage Definitions",
                description="Lists ordered SOC case lifecycle pipeline stages.",
                category="case_config",
                handler=self.list_case_stage_definitions,
                mcp_tool_name="list_case_stage_definitions",
                composed=False,
                evidence_path="evidence/case_config/stages/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.close_definition.list",
                name="List Case Close Definitions",
                description="Catalogs predefined close reasons and root causes for closing cases.",
                category="case_config",
                handler=self.list_case_close_definitions,
                mcp_tool_name="list_case_close_definitions",
                composed=False,
                evidence_path="evidence/case_config/close_definitions/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.close_parameter.list",
                name="List Case Close Dynamic Parameters",
                description="Discovers dynamic form fields and custom field schemas required when closing cases.",
                category="case_config",
                handler=self.list_case_close_dynamic_parameters,
                mcp_tool_name="list_case_close_dynamic_parameters",
                composed=False,
                evidence_path="evidence/case_config/close_parameters/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.title_settings.get",
                name="Get Case Title Naming Rules",
                description="Retrieves priority rules for automated SOAR case naming.",
                category="case_config",
                handler=self.get_case_title_settings,
                mcp_tool_name="get_case_title_settings",
                composed=False,
                evidence_path="evidence/case_config/title_settings/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.view.search",
                name="Search Case and Alert Views",
                description="Discovers and filters layout view templates for Cases, Alerts, and Detections.",
                category="case_config",
                handler=self.search_case_views,
                mcp_tool_name="search_case_views",
                composed=False,
                evidence_path="evidence/case_config/views/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.view.get",
                name="Case View Deep Inspection",
                description="Retrieves deep inspection of a specific view layout template and widget hierarchy.",
                category="case_config",
                handler=self.get_case_view,
                mcp_tool_name="get_case_view",
                composed=False,
                evidence_path="evidence/case_config/views/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.custom_field.search",
                name="Search Custom Fields",
                description="Lists and filters custom typed fields across Case and Alert scopes.",
                category="case_config",
                handler=self.search_custom_fields,
                mcp_tool_name="search_custom_fields",
                composed=False,
                evidence_path="evidence/case_config/custom_fields/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.custom_field.get",
                name="Custom Field Deep Inspection",
                description="Retrieves deep inspection of a single custom field definition and ordered option values.",
                category="case_config",
                handler=self.get_custom_field,
                mcp_tool_name="get_custom_field",
                composed=False,
                evidence_path="evidence/case_config/custom_fields/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.calculated_field.search",
                name="Search Calculated Fields",
                description="Lists and filters calculated field formula definitions.",
                category="case_config",
                handler=self.search_calculated_fields,
                mcp_tool_name="search_calculated_fields",
                composed=False,
                evidence_path="evidence/case_config/calculated_fields/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.calculated_field.get",
                name="Calculated Field Deep Inspection",
                description="Retrieves deep inspection of a single calculated field definition.",
                category="case_config",
                handler=self.get_calculated_field,
                mcp_tool_name="get_calculated_field",
                composed=False,
                evidence_path="evidence/case_config/calculated_fields/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.alert_grouping.rule.search",
                name="Search Alert Grouping Rules",
                description="Discovers and filters SOAR alert grouping rules determining case clustering.",
                category="case_config",
                handler=self.search_alert_grouping_rules,
                mcp_tool_name="search_alert_grouping_rules",
                composed=False,
                evidence_path="evidence/case_config/alert_grouping/rules/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.alert_grouping.rule.get",
                name="Alert Grouping Rule Deep Inspection",
                description="Retrieves deep inspection of a single alert grouping rule including entity types and category details.",
                category="case_config",
                handler=self.get_alert_grouping_rule,
                mcp_tool_name="get_alert_grouping_rule",
                composed=False,
                evidence_path="evidence/case_config/alert_grouping/rules/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="case_config.alert_grouping.settings.get",
                name="Get Alert Grouping Global Settings",
                description="Retrieves global SOAR alert grouping configuration parameters including timeframes and algorithms.",
                category="case_config",
                handler=self.get_alert_grouping_settings,
                mcp_tool_name="get_alert_grouping_settings",
                composed=False,
                evidence_path="evidence/case_config/alert_grouping/settings/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.data_retention.get",
                name="Get Data Retention Settings",
                description="Retrieves SOAR data retention configuration and per-environment policy settings.",
                category="soar_settings",
                handler=self.get_data_retention_settings,
                mcp_tool_name="get_data_retention_settings",
                composed=False,
                evidence_path="evidence/soar_settings/data_retention/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.environment.search",
                name="Search Multi-Tenancy Environments",
                description="Discovers and filters multi-tenancy environment boundaries within the SOAR tenant.",
                category="soar_settings",
                handler=self.search_environments,
                mcp_tool_name="search_environments",
                composed=False,
                evidence_path="evidence/soar_settings/environments/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.environment.get",
                name="Environment Deep Inspection",
                description="Retrieves deep configuration details of a single multi-tenancy environment.",
                category="soar_settings",
                handler=self.get_environment,
                mcp_tool_name="get_environment",
                composed=False,
                evidence_path="evidence/soar_settings/environments/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.environment_group.search",
                name="Search Environment Groups",
                description="Discovers and lists logical groupings of multi-tenancy environments.",
                category="soar_settings",
                handler=self.search_environment_groups,
                mcp_tool_name="search_environment_groups",
                composed=False,
                evidence_path="evidence/soar_settings/environment_groups/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.remote_agent.search",
                name="Search Remote SOAR Agents",
                description="Discovers and filters remote execution agents, bindings, and active health states.",
                category="soar_settings",
                handler=self.search_remote_agents,
                mcp_tool_name="search_remote_agents",
                composed=False,
                evidence_path="evidence/soar_settings/remote_agents/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.remote_agent.get",
                name="Remote SOAR Agent Deep Inspection",
                description="Retrieves deep configuration of a remote agent including certificates and installer links.",
                category="soar_settings",
                handler=self.get_remote_agent,
                mcp_tool_name="get_remote_agent",
                composed=False,
                evidence_path="evidence/soar_settings/remote_agents/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.email_settings.get",
                name="Get SOAR Email Transport Settings",
                description="Retrieves composite email transport configuration combining custom SMTP and Google defaults.",
                category="soar_settings",
                handler=self.get_email_settings,
                mcp_tool_name="get_email_settings",
                composed=False,
                evidence_path="evidence/soar_settings/email_settings/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.support_settings.get",
                name="Get Google Support Access Settings",
                description="Retrieves Google Support access delegation parameters including roles, environments, and expiry.",
                category="soar_settings",
                handler=self.get_support_settings,
                mcp_tool_name="get_support_settings",
                composed=False,
                evidence_path="evidence/soar_settings/support_settings/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.network.search",
                name="Search SOAR Networks",
                description="Discovers and filters customer-defined CIDR network address ranges and environment mappings.",
                category="soar_settings",
                handler=self.search_soar_networks,
                mcp_tool_name="search_soar_networks",
                composed=False,
                evidence_path="evidence/soar_settings/networks/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.network.get",
                name="SOAR Network Deep Inspection",
                description="Retrieves complete configuration for a single customer-defined CIDR network.",
                category="soar_settings",
                handler=self.get_soar_network,
                mcp_tool_name="get_soar_network",
                composed=False,
                evidence_path="evidence/soar_settings/networks/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.domain.search",
                name="Search SOAR Domains",
                description="Discovers and filters customer-approved domain names and environment mappings.",
                category="soar_settings",
                handler=self.search_soar_domains,
                mcp_tool_name="search_soar_domains",
                composed=False,
                evidence_path="evidence/soar_settings/domains/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.domain.get",
                name="SOAR Domain Deep Inspection",
                description="Retrieves complete configuration for a single approved customer domain.",
                category="soar_settings",
                handler=self.get_soar_domain,
                mcp_tool_name="get_soar_domain",
                composed=False,
                evidence_path="evidence/soar_settings/domains/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.custom_list.search",
                name="Search SOAR Custom Lists",
                description="Discovers and filters SOAR custom key-value style retention lists by query, category, and environment.",
                category="soar_settings",
                handler=self.search_soar_custom_lists,
                mcp_tool_name="search_soar_custom_lists",
                composed=False,
                evidence_path="evidence/soar_settings/custom_lists/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.custom_list.get",
                name="SOAR Custom List Deep Inspection",
                description="Retrieves complete configuration for a single SOAR custom list record.",
                category="soar_settings",
                handler=self.get_soar_custom_list,
                mcp_tool_name="get_soar_custom_list",
                composed=False,
                evidence_path="evidence/soar_settings/custom_lists/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.email_template.search",
                name="Search Email Templates",
                description="Discovers and filters plain text and HTML email templates used in SOAR playbooks.",
                category="soar_settings",
                handler=self.search_email_templates,
                mcp_tool_name="search_email_templates",
                composed=False,
                evidence_path="evidence/soar_settings/email_templates/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.email_template.get",
                name="Email Template Deep Inspection",
                description="Retrieves complete email template definition including markup and body content.",
                category="soar_settings",
                handler=self.get_email_template,
                mcp_tool_name="get_email_template",
                composed=False,
                evidence_path="evidence/soar_settings/email_templates/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.entities_blocklist.search",
                name="Search Entities Blocklist",
                description="Discovers and filters entity extraction noise-reduction blocklists.",
                category="soar_settings",
                handler=self.search_entities_blocklists,
                mcp_tool_name="search_entities_blocklists",
                composed=False,
                evidence_path="evidence/soar_settings/entities_blocklists/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.entities_blocklist.get",
                name="Entities Blocklist Deep Inspection",
                description="Retrieves complete configuration for a single entity blocklist entry.",
                category="soar_settings",
                handler=self.get_entities_blocklist,
                mcp_tool_name="get_entities_blocklist",
                composed=False,
                evidence_path="evidence/soar_settings/entities_blocklists/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.sla_definition.search",
                name="Search SLA Definitions",
                description="Discovers and filters Service Level Agreement definitions across stages and priorities.",
                category="soar_settings",
                handler=self.search_sla_definitions,
                mcp_tool_name="search_sla_definitions",
                composed=False,
                evidence_path="evidence/soar_settings/sla_definitions/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.sla_definition.get",
                name="SLA Definition Deep Inspection",
                description="Retrieves complete SLA parameters for a single SLA rule.",
                category="soar_settings",
                handler=self.get_sla_definition,
                mcp_tool_name="get_sla_definition",
                composed=False,
                evidence_path="evidence/soar_settings/sla_definitions/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.request_template.search",
                name="Search Request Templates",
                description="Discovers and filters SOAR manual case request form templates.",
                category="soar_settings",
                handler=self.search_request_templates,
                mcp_tool_name="search_request_templates",
                composed=False,
                evidence_path="evidence/soar_settings/request_templates/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.request_template.get",
                name="Request Template Deep Inspection",
                description="Retrieves complete form field definitions and options for a single request template.",
                category="soar_settings",
                handler=self.get_request_template,
                mcp_tool_name="get_request_template",
                composed=False,
                evidence_path="evidence/soar_settings/request_templates/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.ingestion_connector.search",
                name="Search Ingestion Connectors",
                description="Discovers and filters configured SOAR ingestion connector instances across integrations.",
                category="soar_settings",
                handler=self.search_soar_ingestion_connectors,
                mcp_tool_name="search_soar_ingestion_connectors",
                composed=False,
                evidence_path="evidence/soar_settings/ingestion_connectors/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.ingestion_connector.get",
                name="Ingestion Connector Deep Inspection",
                description="Retrieves complete configuration for a single SOAR ingestion connector instance.",
                category="soar_settings",
                handler=self.get_soar_ingestion_connector,
                mcp_tool_name="get_soar_ingestion_connector",
                composed=False,
                evidence_path="evidence/soar_settings/ingestion_connectors/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.webhook.search",
                name="Search SOAR Webhooks",
                description="Discovers and filters configured SOAR event ingestion webhooks.",
                category="soar_settings",
                handler=self.search_soar_webhooks,
                mcp_tool_name="search_soar_webhooks",
                composed=False,
                evidence_path="evidence/soar_settings/webhooks/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soar.webhook.get",
                name="SOAR Webhook Deep Inspection",
                description="Retrieves complete configuration and schema mapping for a single SOAR event ingestion webhook.",
                category="soar_settings",
                handler=self.get_soar_webhook,
                mcp_tool_name="get_soar_webhook",
                composed=False,
                evidence_path="evidence/soar_settings/webhooks/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.list",
                name="List Data Tables",
                description="Lists all structured Data Tables defined in Chronicle SIEM.",
                category="data_table",
                handler=self.list_data_tables,
                mcp_tool_name="list_data_tables",
                composed=False,
                evidence_path="evidence/data_table/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.get",
                name="Get Data Table",
                description="Retrieves schema, columns, TTL, and metadata for a Chronicle SIEM Data Table.",
                category="data_table",
                handler=self.get_data_table,
                mcp_tool_name="get_data_table",
                composed=False,
                evidence_path="evidence/data_table/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.create",
                name="Create Data Table",
                description="Creates a new structured Data Table with typed column definitions in Chronicle SIEM.",
                category="data_table",
                handler=self.create_data_table,
                mcp_tool_name="create_data_table",
                composed=False,
                evidence_path="evidence/data_table/create",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.patch",
                name="Update Data Table",
                description="Updates description, TTL, or scope info of an existing Chronicle SIEM Data Table.",
                category="data_table",
                handler=self.patch_data_table,
                mcp_tool_name="patch_data_table",
                composed=False,
                evidence_path="evidence/data_table/patch",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.delete",
                name="Delete Data Table",
                description="Deletes a structured Data Table from Chronicle SIEM.",
                category="data_table",
                handler=self.delete_data_table,
                mcp_tool_name="delete_data_table",
                composed=False,
                evidence_path="evidence/data_table/delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.list_rows",
                name="List Data Table Rows",
                description="Queries and filters rows contained within a Chronicle SIEM Data Table.",
                category="data_table",
                handler=self.list_data_table_rows,
                mcp_tool_name="list_data_table_rows",
                composed=False,
                evidence_path="evidence/data_table/list_rows",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.add_rows",
                name="Add Data Table Rows",
                description="Creates or appends rows in bulk to a Chronicle SIEM Data Table.",
                category="data_table",
                handler=self.add_data_table_rows,
                mcp_tool_name="add_data_table_rows",
                composed=False,
                evidence_path="evidence/data_table/add_rows",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.delete_row",
                name="Delete Data Table Row",
                description="Deletes a single row from a Chronicle SIEM Data Table by row ID.",
                category="data_table",
                handler=self.delete_data_table_row,
                mcp_tool_name="delete_data_table_row",
                composed=False,
                evidence_path="evidence/data_table/delete_row",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="data_table.audit_health",
                name="Audit Data Table Governance & Lineage",
                description="Audits Data Tables across the tenant for lifecycle recency, schema integrity, and detection false-negative risks.",
                category="data_table",
                handler=self.audit_data_table_health,
                mcp_tool_name="audit_data_tables",
                composed=True,
                uses=("data_table.list", "rule.list"),
                evidence_path="evidence/data_table/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.list",
                name="Search Detection Rules",
                description="Lists custom YARA-L detection rules in Chronicle SIEM.",
                category="rule",
                handler=self.list_rules,
                mcp_tool_name="list_rules",
                composed=False,
                evidence_path="evidence/rule/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.get",
                name="Get Detection Rule",
                description="Retrieves full details and YARA-L logic of a detection rule.",
                category="rule",
                handler=self.get_rule,
                mcp_tool_name="get_rule",
                composed=False,
                evidence_path="evidence/rule/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.verify",
                name="Verify Rule Text",
                description="Validates YARA-L 2.0 rule syntax against the Chronicle compiler.",
                category="rule",
                handler=self.verify_rule,
                mcp_tool_name="verify_rule_text",
                composed=False,
                evidence_path="evidence/rule/verify",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.create",
                name="Create Detection Rule",
                description="Creates a new YARA-L detection rule in Chronicle SIEM.",
                category="rule",
                handler=self.create_rule,
                mcp_tool_name="create_rule",
                composed=False,
                evidence_path="evidence/rule/create",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.patch",
                name="Patch Detection Rule",
                description="Updates the YARA-L logic of an existing detection rule.",
                category="rule",
                handler=self.patch_rule,
                mcp_tool_name="patch_rule",
                composed=False,
                evidence_path="evidence/rule/patch",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.delete",
                name="Delete Detection Rule",
                description="Deletes a custom detection rule from Chronicle SIEM.",
                category="rule",
                handler=self.delete_rule,
                mcp_tool_name="delete_rule",
                composed=False,
                evidence_path="evidence/rule/delete",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.revisions",
                name="List Rule Revisions",
                description="Lists historical revisions and version history of a detection rule.",
                category="rule",
                handler=self.list_rule_revisions,
                mcp_tool_name="list_rule_revisions",
                composed=False,
                evidence_path="evidence/rule/revisions",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.deployment.list",
                name="List Rule Deployments",
                description="Lists deployment, frequency, and alerting status for all detection rules.",
                category="rule",
                handler=self.list_rule_deployments,
                mcp_tool_name="list_rule_deployments",
                composed=False,
                evidence_path="evidence/rule/deployment/list",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.deployment.get",
                name="Get Rule Deployment",
                description="Retrieves deployment, frequency, and alerting status of a rule.",
                category="rule",
                handler=self.get_rule_deployment,
                mcp_tool_name="get_rule_deployment",
                composed=False,
                evidence_path="evidence/rule/deployment/get",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.deployment.update",
                name="Update Rule Deployment",
                description="Updates deployment properties (enabled, alerting, frequency) of a rule.",
                category="rule",
                handler=self.update_rule_deployment,
                mcp_tool_name="update_rule_deployment",
                composed=False,
                evidence_path="evidence/rule/deployment/update",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.errors",
                name="List Rule Execution Errors",
                description="Lists runtime and execution errors across detection rules.",
                category="rule",
                handler=self.list_rule_errors,
                mcp_tool_name="list_rule_errors",
                composed=False,
                evidence_path="evidence/rule/errors",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.audit_health",
                name="Audit Detection Rule Health",
                description="Audits and correlates Chronicle YARA-L rules, execution errors, latency observability, and detection decay.",
                category="rule",
                handler=self.audit_rule_health,
                mcp_tool_name="audit_rule_health",
                composed=True,
                uses=(
                    "rule.list",
                    "rule.errors",
                    "rule.deployment.list",
                    "rule.decay.telemetry",
                    "curated_detections.deployments.list",
                    "dashboard.execute_query",
                ),
                evidence_path="evidence/rule/audit_health",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.decay.audit",
                name="Audit Detection Rule Decay",
                description="Audits detection rules for compilation breakage, silence, staleness, and unpopulated UDM fields with DPS scoring.",
                category="rule",
                handler=self.audit_rule_decay,
                mcp_tool_name="audit_rule_decay",
                composed=True,
                uses=(
                    "rule.list",
                    "rule.get",
                    "rule.verify",
                    "rule.deployment.list",
                    "rule.decay.telemetry",
                    "dashboard.execute_query",
                ),
                evidence_path="evidence/rule/decay_audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.decay.telemetry",
                name="Query Rule Detection Telemetry (90-Day)",
                description="Queries 90-day detection count aggregations using authoritative native detection schema.",
                category="rule",
                handler=self.get_rule_detection_counts,
                mcp_tool_name="get_rule_detection_counts",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/rule/decay_telemetry",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.detection_series",
                name="Query Bucketed Rule Detection Series",
                description="Per-rule detection counts bucketed by hour or day (UTC) over a lookback window, in one dashboard query.",
                category="rule",
                handler=self.get_rule_detection_series,
                mcp_tool_name="get_rule_detection_series",
                composed=False,
                # Explicit: "detection_series" is not a known read verb. One
                # aggregated dashboard query with a fixed row limit -> bounded.
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/rule/detection_series",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.conflict.audit",
                name="Audit Detection Rule Conflicts & Overlaps",
                description="Performs semantic dual-rule YARA-L logic comparison, identifies REDUNDANCY, OVERLAP, CONTRADICTION, or SCOPE GAPS, and computes Conflict Overlap Score (COS: 0-100).",
                category="rule",
                handler=self.audit_rule_conflicts,
                mcp_tool_name="audit_rule_conflicts",
                composed=True,
                uses=("rule.get", "rule.deployment.list"),
                evidence_path="evidence/rule/conflict_audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.conflict.batch_audit",
                name="Batch Audit Rule Conflicts & Overlaps",
                description="Discovers and ranks semantic rule conflicts across tenant active rules with batch chunking and Evidence Fabric persistence.",
                category="rule",
                handler=self.batch_audit_rule_conflicts,
                mcp_tool_name="batch_audit_rule_conflicts",
                composed=True,
                uses=("rule.list", "rule.deployment.list", "rule.conflict.audit"),
                evidence_path="evidence/rule/conflict_batch_audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.similarity.search",
                name="Search Similar Detection Rules",
                description="Finds semantically similar detection rules using 768-d text-embedding-004 vectors and cosine similarity.",
                category="rule",
                handler=self.find_similar_rules,
                mcp_tool_name="find_similar_rules",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/rule/similarity_search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.embeddings.sync",
                name="Synchronize Rule Embeddings",
                description="Batch computes and stores text-embedding-004 vector embeddings for all active tenant rules.",
                category="rule",
                handler=self.sync_rule_embeddings,
                mcp_tool_name="sync_rule_embeddings",
                composed=False,
                kind="primitive",
                evidence_path="evidence/rule/embeddings_sync",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="rule.audit",
                name="Unified Detection Rule Repository Audit",
                description="Performs an end-to-end repository audit across custom and curated rules, synchronizing vector embeddings, calculating DPS decay, discovering cross-rule conflicts, and updating Firestore Evidence Fabric.",
                category="rule",
                handler=self.audit_rules,
                mcp_tool_name="audit_rules",
                composed=True,
                uses=(
                    "rule.list",
                    "rule.deployment.list",
                    "rule.errors",
                    "rule.embeddings.sync",
                    "rule.decay.audit",
                    "rule.conflict.batch_audit",
                ),
                evidence_path="evidence/rule/audit",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="gcp_logging.search",
                name="Search GCP Cloud Logging for SecOps",
                description="Queries Google Cloud Logging for SecOps audit, error, parser, and forwarder telemetry via ADC.",
                category="gcp_logging",
                handler=self.query_cloud_logging,
                mcp_tool_name="query_gcp_cloud_logging",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/gcp_logging/search",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="gcp_monitoring.time_series",
                name="Query GCP Cloud Monitoring Metrics for SecOps",
                description="Queries Google Cloud Monitoring time series for Chronicle ingestion, normalizer, agent, and API metrics.",
                category="gcp_monitoring",
                handler=self.query_cloud_monitoring,
                mcp_tool_name="query_gcp_cloud_metrics",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/gcp_monitoring/time_series",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="gcp_status.incidents.query",
                name="Query Google Cloud SecOps Service Status Incidents",
                description="Queries Google Cloud Security Status feed for active and historical disruptions, maintenance, and outages affecting Google SecOps.",
                category="gcp_status",
                handler=self.query_cloud_status_incidents,
                mcp_tool_name="query_cloud_status_incidents",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/gcp_status/incidents",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="gcp_status.report.audit",
                name="Audit Google Cloud SecOps Platform Health",
                description="Audits overall Google SecOps service health, active incidents, recent resolutions, and regional impact from Google Cloud Status.",
                category="gcp_status",
                handler=self.audit_cloud_service_status,
                mcp_tool_name="audit_cloud_service_status",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/gcp_status/report",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="identity.iam.bindings",
                name="Audit GCP IAM Bindings for Chronicle",
                description="Inspects project IAM policy for predefined Chronicle roles and custom role assignments.",
                category="identity",
                handler=self.get_chronicle_iam_bindings,
                mcp_tool_name="get_chronicle_iam_bindings",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/identity/iam_bindings",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="identity.custom_roles.list",
                name="List Custom GCP IAM Roles with Chronicle Permissions",
                description="Discovers custom GCP IAM roles within the project granting chronicle.* permissions.",
                category="identity",
                handler=self.get_chronicle_custom_roles,
                mcp_tool_name="get_chronicle_custom_roles",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/identity/custom_roles",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="identity.inventory.report",
                name="Fetch SecOps Inventory Identity Governance Report",
                description="Retrieves identity access insights and workforce pool assignments from SecOps Inventory.",
                category="identity",
                handler=self.fetch_inventory_identity_report,
                mcp_tool_name="fetch_inventory_identity_report",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/identity/inventory_report",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="log_cost.analyze",
                name="Analyze Log Ingestion Cost and FinOps Optimization",
                description="Analyzes ingestion telemetry from Chronicle, isolates bloated log types, models costs across Standard/Enterprise/Enterprise Plus tiers, and synthesizes FinOps recommendations.",
                category="log",
                handler=self.analyze_log_costs,
                mcp_tool_name="analyze_log_costs",
                composed=True,
                uses=("dashboard.execute_query",),
                evidence_path="evidence/log_cost/analyze",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="log_cost.get_latest",
                name="Get Latest Log Cost and FinOps Analysis Report",
                description="Retrieves the most recent log cost and FinOps analysis report from Evidence Fabric.",
                category="log",
                handler=self.get_latest_log_costs,
                mcp_tool_name="get_latest_log_costs",
                composed=False,
                kind="query",
                cardinality="single",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="ingestion.labels.analyze",
                name="Analyze Active Ingestion Labels",
                description="Analyzes active ingestion labels across log types via native GoogleSQL, classifying auto-generated vs custom tags.",
                category="ingestion",
                handler=self.analyze_ingestion_labels,
                mcp_tool_name="analyze_ingestion_labels",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/ingestion/labels",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="ingestion.namespaces.analyze",
                name="Analyze Active UDM Namespaces",
                description="Analyzes active UDM namespaces and flags potential RFC 1918 overlapping IP collisions across network telemetry.",
                category="ingestion",
                handler=self.analyze_namespaces,
                mcp_tool_name="analyze_namespaces",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/ingestion/namespaces",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="ingestion.rbac_alignment.audit",
                name="Audit Data RBAC Alignment",
                description="Audits Data Access Labels against active telemetry tags and namespaces, detecting unreferenced or broken scoping rules.",
                category="ingestion",
                handler=self.audit_data_rbac_alignment,
                mcp_tool_name="audit_data_rbac_alignment",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/ingestion/rbac_alignment",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="ingestion.labels_and_namespaces.analyze",
                name="Analyze Ingestion Labels, Namespaces and Data RBAC Hygiene",
                description="Performs unified hygiene audit across active ingestion labels, UDM namespaces, default untagged telemetry volume, and Data Access Scopes.",
                category="ingestion",
                handler=self.analyze_labels_and_namespaces,
                mcp_tool_name="analyze_labels_and_namespaces",
                composed=True,
                uses=(
                    "ingestion.labels.analyze",
                    "ingestion.namespaces.analyze",
                    "ingestion.rbac_alignment.audit",
                    "data_rbac.label.search",
                ),
                evidence_path="evidence/ingestion/labels_and_namespaces",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="tenant.profile.identity_fidelity",
                name="Profile Tenant UDM Identity Fidelity Density",
                description="Executes native GoogleSQL pipe aggregation against live events to measure distinct user identity density per log type.",
                category="tenant_profiling",
                handler=self.get_identity_fidelity,
                mcp_tool_name="get_identity_fidelity",
                composed=True,
                uses=("dashboard.execute_query",),
                evidence_path="evidence/tenant_profiling/identity_fidelity",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="tenant.profile.graph_lineage",
                name="Profile Tenant Entity Graph Lineage & Longevity",
                description="Executes native GoogleSQL pipe aggregation against live graph table to map entity resolution provenance and longevity.",
                category="tenant_profiling",
                handler=self.get_entity_graph_lineage,
                mcp_tool_name="get_entity_graph_lineage",
                composed=True,
                uses=("dashboard.execute_query",),
                evidence_path="evidence/tenant_profiling/graph_lineage",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="tenant.profile.volume_pareto",
                name="Profile Tenant Telemetry Volume Pareto",
                description="Executes native GoogleSQL pipe aggregation against live events to rank log sources by raw ingestion volume.",
                category="tenant_profiling",
                handler=self.get_log_source_volume_pareto,
                mcp_tool_name="get_log_source_volume_pareto",
                composed=True,
                uses=("dashboard.execute_query",),
                evidence_path="evidence/tenant_profiling/volume_pareto",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="tenant.profile.generate",
                name="Generate Comprehensive Tenant Telemetry Profile",
                description="Executes deep tenant cartography across graph, identity, and volume to synthesize an attested tenant telemetry profile.",
                category="tenant_profiling",
                handler=self.generate_tenant_telemetry_profile,
                mcp_tool_name="generate_tenant_telemetry_profile",
                composed=True,
                uses=(
                    "tenant.profile.identity_fidelity",
                    "tenant.profile.graph_lineage",
                    "tenant.profile.volume_pareto",
                    "dashboard.execute_query",
                ),
                evidence_path="evidence/tenant_profiling/generate",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soc.briefing.shift_handover",
                name="Generate Shift Handover Briefing",
                description="Deterministically aggregates work queue deltas, resolved issues, active agent leases, applied changes, and verified healthy baselines into a shift briefing.",
                category="operational_intelligence",
                handler=self.generate_shift_briefing,
                mcp_tool_name="generate_shift_briefing",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/operational_intelligence/shift_briefing",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soc.briefing.posture_snapshot",
                name="Generate SOC Knowledge & Posture Snapshot",
                description="Compiles complete tenant operational posture, subsystem health indicators, assertion freshness distributions, and surfaced Knowledge Gaps.",
                category="operational_intelligence",
                handler=self.generate_posture_snapshot,
                mcp_tool_name="generate_posture_snapshot",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/operational_intelligence/posture_snapshot",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="soc.briefing.entity_dossier",
                name="Get Composite Entity Dossier",
                description="Synthesizes cross-agent factual assertions, health statuses, linked issues, and knowledge gaps for a specific operational entity.",
                category="operational_intelligence",
                handler=self.get_composite_entity_dossier,
                mcp_tool_name="get_composite_entity_dossier",
                composed=False,
                kind="query",
                cardinality="single",
                evidence_path="evidence/operational_intelligence/entity_dossier",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="mitre.sync_cache",
                name="Sync MITRE Rules to Cache",
                description="Synchronizes customer and curated Google SecOps detection rules into Firestore cache with parsed MITRE technique IDs and tactics.",
                category="detection_engineering",
                handler=self.sync_mitre_rules,
                mcp_tool_name="sync_mitre_rules_cache",
                composed=False,
                side_effects=["write_rule_cache"],
                evidence_path="evidence/mitre/sync_rules",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="mitre.analyze_coverage",
                name="Analyze MITRE ATT&CK Strategic Coverage",
                description="Evaluates cached detection rules and live ingestion telemetry against MITRE ATT&CK matrix and threat profiles to determine coverage score and gaps.",
                category="threat_intelligence",
                handler=self.analyze_mitre_coverage,
                mcp_tool_name="analyze_mitre_coverage",
                composed=True,
                uses=("mitre.sync_cache",),
                evidence_path="evidence/mitre/coverage_analysis",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="mitre.get_technique_rules",
                name="Get Rules for MITRE Technique",
                description="Retrieves all custom and curated detection rules mapped to a specific MITRE ATT&CK technique ID.",
                category="threat_intelligence",
                handler=self.get_technique_rules,
                mcp_tool_name="get_technique_rules",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/mitre/technique_rules",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="mitre.list_threat_profiles",
                name="List MITRE Threat Profiles",
                description="Lists available threat profiles with baseline technique counts and high-risk weight mappings.",
                category="threat_intelligence",
                handler=self.list_mitre_threat_profiles,
                mcp_tool_name="list_mitre_threat_profiles",
                composed=False,
                kind="query",
                cardinality="bounded",
                evidence_path="evidence/mitre/threat_profiles",
            )
        )
        self.registry.register(
            WorkflowCapability(
                capability_id="mitre.generate_report",
                name="Generate MITRE Strategic Coverage Report",
                description="Generates an executive Markdown report and tactical gap analysis for MITRE ATT&CK posture.",
                category="threat_intelligence",
                handler=self.generate_mitre_report,
                mcp_tool_name="generate_mitre_report",
                composed=True,
                uses=("mitre.analyze_coverage",),
                evidence_path="evidence/mitre/coverage_report",
            )
        )


    def execute(
        self,
        capability_id: str,
        *args: Any,
        enforce_agent_policy: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Universal capability dispatcher.

        Executes any registered workflow capability by its capability ID (e.g. 'dashboards.health_check')
        or its MCP tool name (e.g. 'run_dashboard_health_check').

        Args:
            capability_id: Capability ID or MCP tool name.
            *args: Positional arguments forwarded to the capability handler.
            enforce_agent_policy: When True, enforces the require-filter policy on
                unbounded queries (Invariant #9) before invoking the handler.
            **kwargs: Keyword arguments forwarded to the capability handler.

        Returns:
            The output returned by the capability's handler.
        """
        return self.registry.execute(
            capability_id,
            *args,
            enforce_agent_policy=enforce_agent_policy,
            **kwargs,
        )

    def search_udm(
        self,
        request: Optional[Union[SearchRequest, str]] = None,
        query: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        lookback_hours: int = 24,
        receive_limit: int = 10000,
        limit: Optional[int] = None,
        batch_size: int = 2000,
        customer_id: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        materialize_budget: Optional[int] = None,
        dialect: Optional[str] = None,
        user_sql: Optional[str] = None,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[Callable[[SearchSession], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
        case_insensitive: bool = True,
        generate_ai_overview: bool = False,
        max_values_per_field: int = 60,
        include_detections: bool = True,
        include_prevalence: bool = True,
        aggregation_fields: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> SearchSession:
        """Executes the canonical UDM Search workflow.

        Supports polymorphic invocation:
        - Passing a pre-built SearchRequest: `engine.search_udm(request)`
        - Passing a query string positionally: `engine.search_udm("metadata.log_type = ...", start_time=..., end_time=...)`
        - Passing flat keyword arguments: `engine.search_udm(query="...", start_time="...", end_time="...")`

        The session carries ``search_stats`` (also exposed as
        ``total_matched``, ``available_count``, ``too_many_events``/``capped``,
        ``timeline``, ``activity_timeline``, ``field_aggregations`` and
        ``aggregates_sampled``). The server materializes at most 30 000
        matches; with ``capped`` every count and aggregate is a sample.

        Options: ``generate_ai_overview`` (default False; the SDK never parsed
        the overview), ``case_insensitive`` (default True, as before),
        ``include_detections`` / ``include_prevalence`` (default True; set
        False for a lean, cheaper request), ``max_values_per_field`` and
        ``aggregation_fields`` (subset of field paths to keep in
        ``field_aggregations``; None keeps all).
        """
        if isinstance(request, SearchRequest):
            req = request
        else:
            q = query or (request if isinstance(request, str) else None)
            if not q:
                raise ValueError("A query string or SearchRequest must be provided to search_udm")
            resolved_start, resolved_end = _resolve_time_window(
                start_time=start_time,
                end_time=end_time,
                lookback_hours=lookback_hours,
            )
            effective_limit = limit if limit is not None else kwargs.get("limit", receive_limit)
            req = SearchRequest(
                query=q,
                start_time=resolved_start,
                end_time=resolved_end,
                receive_limit=effective_limit,
                batch_size=batch_size,
                customer_id=customer_id,
                project_id=project_id,
                location=location,
                materialize_budget=materialize_budget,
                dialect=dialect or kwargs.get("dialect"),
                user_sql=user_sql or kwargs.get("user_sql"),
                case_insensitive=case_insensitive,
                generate_ai_overview=generate_ai_overview,
                max_values_per_field=max_values_per_field,
                include_detections=include_detections,
                include_prevalence=include_prevalence,
                aggregation_fields=list(aggregation_fields) if aggregation_fields is not None else None,
            )

        return self._search_udm_wf.execute(
            request=req,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
        )

    def search_udm_stats(
        self,
        request: Optional[Union[StatsSearchRequest, str]] = None,
        query: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        lookback_hours: int = 24,
        max_events: int = 10000,
        case_insensitive: bool = True,
        generate_ai_overview: bool = True,
        max_values_per_field: int = 60,
        dialect: Optional[str] = None,
        user_sql: Optional[str] = None,
        on_batch: Optional[Callable[[StatsSearchResult, StatsSearchSession], None]] = None,
        on_state_change: Optional[Callable[[Any, Any, StatsSearchSession], None]] = None,
        cancel_token: Optional[Any] = None,
        poll_interval: float = 0.5,
        max_poll_seconds: float = 120.0,
        include_detections: bool = True,
        include_prevalence: bool = True,
    ) -> StatsSearchSession:
        """Executes the canonical UDM Stats Search (Aggregation & Analytics) workflow.

        ``case_insensitive``, ``generate_ai_overview``, ``max_values_per_field``,
        ``include_detections`` and ``include_prevalence`` are sent to the
        search view (they used to be ignored and hardcoded). With
        ``case_insensitive=True`` grouped string values come back lower-cased.
        """
        if isinstance(request, StatsSearchRequest):
            req = request
        else:
            q = query or (request if isinstance(request, str) else None)
            if not q:
                raise ValueError("A query string or StatsSearchRequest must be provided")
            resolved_start, resolved_end = _resolve_time_window(
                start_time=start_time,
                end_time=end_time,
                lookback_hours=lookback_hours,
            )
            req = StatsSearchRequest(
                query=q,
                start_time=resolved_start,
                end_time=resolved_end,
                max_events=max_events,
                case_insensitive=case_insensitive,
                generate_ai_overview=generate_ai_overview,
                max_values_per_field=max_values_per_field,
                dialect=dialect,
                user_sql=user_sql,
                include_detections=include_detections,
                include_prevalence=include_prevalence,
            )

        return self._search_udm_stats_wf.execute(
            request=req,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
            poll_interval=poll_interval,
            max_poll_seconds=max_poll_seconds,
        )

    def aggregate_udm(
        self,
        filter: str = "",
        group_by: Optional[List[str]] = None,
        time_bucket: Optional[str] = None,
        lookback_hours: int = 24,
        limit: int = 500,
        metric: str = "count",
        distinct_field: Optional[str] = None,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        clear_cache: Optional[bool] = None,
    ) -> UdmAggregateResult:
        """Counts UDM events by 0-2 allow-listed fields and an optional UTC hour/day bucket.

        One synchronous ``dashboardQueries:execute`` call (GoogleSQL pipe
        syntax). ``group_by`` defaults to ``["metadata.log_type"]``; pass ``[]``
        for a single total. ``filter`` is a restricted UDM-search predicate
        (``field = "value"``, ``!=``, ``<``/``<=``/``>``/``>=``, AND/OR/NOT,
        parentheses) over the same allow-list, translated to SQL with escaped
        literals; anything else raises ``UdmFilterError``. ``metric`` is
        ``count`` or ``count_distinct`` (with a scalar ``distinct_field``).

        Bounds (ValueError): lookback / window <= 168 h, 1 <= limit <= 2000,
        at most 2 group_by fields. ``truncated`` is True when more than
        ``limit`` rows exist (the SDK requests limit + 1). Query errors raise.
        See ``engine/workflows/udm_aggregate.py`` for the allow-list and the
        repeated-field (per-value) semantics.
        """
        return self._aggregate_udm_wf.execute(
            filter=filter,
            group_by=["metadata.log_type"] if group_by is None else group_by,
            time_bucket=time_bucket,
            lookback_hours=lookback_hours,
            limit=limit,
            metric=metric,
            distinct_field=distinct_field,
            start_time=start_time,
            end_time=end_time,
            clear_cache=clear_cache,
        )

    def find_udm_field_values(
        self,
        query: str,
        page_size: int = 20,
        page_token: Optional[str] = None,
    ) -> UdmFieldValueMatches:
        """Finds UDM field paths whose recent values match ``query`` (autocomplete).

        Read-only ``GET :findUdmFieldValues``. Matches can come from any UDM
        field (including user ids and registry values); project before showing
        them to untrusted users.
        """
        return self._find_udm_field_values_wf.execute(query=query, page_size=page_size, page_token=page_token)

    def translate_udm_query(self, text: str) -> UdmQueryTranslation:
        """Translates natural language into a UDM search query (+ optional time range).

        Read-only ``POST :translateUdmQuery``; does not run the query. Whether
        it consumes Gemini quota is UNKNOWN.
        """
        return self._translate_udm_query_wf.execute(text=text)

    def query_product_source_stats(
        self,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        lookback_hours: int = 24,
    ) -> ProductSourceStatsBatch:
        """Queries product source statistics and ingested data sizes across the evaluation window."""
        return self._query_product_source_stats_wf.execute(
            start_time=start_time,
            end_time=end_time,
            lookback_hours=lookback_hours,
        )

    def validate_raw_log_query(
        self,
        query: str,
        allow_unreplaced_placeholders: bool = False,
    ) -> RawLogValidationResult:
        """Validates raw log search query syntax against Chronicle query compiler."""
        return self._validate_raw_log_query_wf.execute(
            query=query,
            allow_unreplaced_placeholders=allow_unreplaced_placeholders,
        )

    def search_raw_logs(
        self,
        query: str,
        start_time: Optional[Union[str, datetime]] = None,
        end_time: Optional[Union[str, datetime]] = None,
        lookback_hours: int = 24,
        log_types: Optional[Union[str, List[str]]] = None,
        case_sensitive: bool = False,
        page_size: int = 1000,
        max_aggregations: int = 60,
    ) -> RawLogSearchResult:
        """Searches unparsed or unnormalized raw log records matching queries, log types, and time ranges."""
        return self._search_raw_logs_wf.execute(
            query=query,
            start_time=start_time,
            end_time=end_time,
            lookback_hours=lookback_hours,
            log_types=log_types,
            case_sensitive=case_sensitive,
            page_size=page_size,
            max_aggregations=max_aggregations,
        )

    def investigate_event(
        self,
        event_ref: Optional[Union[EventReference, Dict[str, Any], str]] = None,
        event_id: Optional[str] = None,
        event: Optional[Union[EventReference, Dict[str, Any], str]] = None,
        eager_load_raw_log: bool = False,
        **kwargs: Any,
    ) -> EventInvestigation:
        """Executes the Event Investigation workflow.

        Accepts:
        - `event_ref`: EventReference, UDM event dictionary/object, or event ID string.
        - `event_id`: Alternative keyword argument for string ID.
        - `event`: Alternative keyword argument for event reference/dict.
        """
        target = event_ref if event_ref is not None else (event_id or event or kwargs.get("id"))
        if target is None:
            raise ValueError("investigate_event requires an event reference, ID string, or event dictionary.")
        return self._investigate_event_wf.execute(
            event_ref=target,
            eager_load_raw_log=eager_load_raw_log,
        )

    def refine_search(
        self,
        base: Union[str, SearchSession],
        filters: Union[List[Union[FieldFilter, Dict[str, Any], Tuple[Any, ...]]], FieldFilter, Dict[str, Any], Tuple[Any, ...]],
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        receive_limit: int = 10000,
        batch_size: int = 2000,
        parent_event_id: Optional[str] = None,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[Callable[[SearchSession], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> SearchSession:
        """Executes the Search Refinement workflow.

        Supports polymorphic filters:
        - List of FieldFilter objects
        - Single FieldFilter object
        - Dict or list of dicts: {"field": "principal.ip", "operator": "=", "value": "1.2.3.4"}
        - Tuple or list of tuples: ("principal.ip", "=", "1.2.3.4") or ("principal.ip", "1.2.3.4")
        """
        coerced_filters = coerce_field_filters(filters)
        return self._refine_search_wf.execute(
            base=base,
            filters=coerced_filters,
            start_time=start_time,
            end_time=end_time,
            receive_limit=receive_limit,
            batch_size=batch_size,
            parent_event_id=parent_event_id,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
        )

    def search_from_entity(
        self,
        entity_type: Union[EntityType, str],
        entity_value: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        lookback_hours: int = 24,
        receive_limit: int = 10000,
        batch_size: int = 2000,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[Callable[[SearchSession], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> SearchSession:
        """Executes a canonical entity pivot search workflow.

        Supports polymorphic entity_type (EntityType enum member or case-insensitive string alias
        such as 'ip', 'hostname', 'user', 'hash', 'domain', 'email').
        """
        coerced_type = coerce_entity_type(entity_type)
        resolved_start, resolved_end = _resolve_time_window(
            start_time=start_time,
            end_time=end_time,
            lookback_hours=lookback_hours,
        )
        return self._search_from_entity_wf.execute(
            entity_type=coerced_type,
            entity_value=entity_value,
            start_time=resolved_start,
            end_time=resolved_end,
            receive_limit=receive_limit,
            batch_size=batch_size,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
        )

    def investigate_case(self, case_id: Union[str, int]) -> CaseInvestigation:
        """Executes the Case Investigation Workspace workflow."""
        return self._investigate_case_wf.execute(case_id=_normalize_case_id(case_id))

    def get_alert_playbook_status(
        self, case_id: Union[str, int], alert_id: Optional[str] = None
    ) -> List[AlertPlaybookStatus]:
        """Returns the attached playbook + status snapshot for alert(s) in a case.

        Tier-1: reuses the Case Investigation workflow (no extra endpoint) and
        surfaces the playbook association already present in the case-alert payload.
        The reported ``status`` is the alert-level ``playbookStatus`` snapshot, not
        the authoritative per-run instance record.

        Args:
            case_id: Numeric case ID (or resource name; the trailing segment is used).
            alert_id: Optional alert identifier/name to filter to a single alert. When
                omitted, status for every alert in the case is returned.

        Returns:
            A list of :class:`AlertPlaybookStatus`. Empty if the case has no alerts
            (or the given ``alert_id`` does not match).
        """
        cid = _normalize_case_id(case_id)
        investigation = self._investigate_case_wf.execute(case_id=cid)
        target = str(alert_id).strip().split("/")[-1] if alert_id else None

        results: List[AlertPlaybookStatus] = []
        for a in investigation.alerts:
            if target is not None and target not in (a.identifier, a.name, a.alert_id):
                continue
            results.append(
                AlertPlaybookStatus(
                    case_id=cid,
                    alert_id=a.alert_id,
                    alert_display_name=a.display_name,
                    attached_playbook_name=a.attached_playbook_name,
                    status=a.playbook_status,
                    run_count=a.playbook_run_count,
                    alert_group_identifier=a.alert_group_identifier,
                )
            )
        return results

    def get_alert_playbook_instances(
        self, case_id: Union[str, int], alert_identifier: str
    ) -> List[PlaybookInstanceCard]:
        """Tier-2: lists authoritative playbook *run instances* for an alert.

        Unlike :meth:`get_alert_playbook_status` (a Tier-1 snapshot from the
        case-alert payload), this queries ``legacyGetWorkflowInstancesCards`` for
        the actual run instances attached to the alert.

        Args:
            case_id: Numeric case ID (or resource name; trailing segment is used).
            alert_identifier: Either the opaque ``alertGroupIdentifier`` or a plain
                alert id/name (auto-resolved to the group identifier).

        Returns:
            A list of :class:`PlaybookInstanceCard`. Each card's
            ``definition_identifier`` can be passed to
            :meth:`get_alert_playbook_instance` for the full run.
        """
        cid = _normalize_case_id(case_id)
        return self._alert_playbook_instances_wf.execute(
            case_id=cid, alert_identifier=alert_identifier
        )

    def get_alert_playbook_instance(
        self,
        case_id: Union[str, int],
        alert_identifier: str,
        definition_identifier: Optional[str] = None,
        should_fetch_steps: bool = True,
        collapse_blocks: bool = True,
        loops_requested_iterations: Optional[List[Any]] = None,
    ) -> PlaybookInstanceRun:
        """Tier-2: retrieves one full playbook run instance incl. the step DAG.

        Wraps ``legacyGetWorkflowInstance``. If ``definition_identifier`` is
        omitted, it is resolved from the alert's first instance card.

        Args:
            case_id: Numeric case ID (or resource name; trailing segment is used).
            alert_identifier: Opaque ``alertGroupIdentifier`` or a plain alert
                id/name (auto-resolved).
            definition_identifier: Playbook UUID. Optional; resolved via the cards
                endpoint when not provided.
            should_fetch_steps: Whether to include per-step execution records.
            collapse_blocks: Whether to collapse nested playbook blocks.
            loops_requested_iterations: Optional loop-iteration selectors.

        Returns:
            A :class:`PlaybookInstanceRun` with runtime status, steps, and the
            execution DAG (``relations``).
        """
        cid = _normalize_case_id(case_id)
        return self._alert_playbook_instances_wf.execute_full(
            case_id=cid,
            alert_identifier=alert_identifier,
            definition_identifier=definition_identifier,
            should_fetch_steps=should_fetch_steps,
            collapse_blocks=collapse_blocks,
            loops_requested_iterations=loops_requested_iterations,
        )

    def get_alert_playbook_executed_path(
        self,
        case_id: Union[str, int],
        alert_identifier: str,
        definition_identifier: Optional[str] = None,
    ) -> List[PlaybookInstanceStep]:
        """Return only the playbook steps that actually executed, in run order.

        Convenience wrapper over :meth:`get_alert_playbook_instance` that collapses
        the full conditional step DAG down to the single branch a given run
        actually traversed (see :meth:`PlaybookInstanceRun.executed_path`). Useful
        for post-incident review and for summarizing "what the playbook did" without
        wading through un-taken branches.

        Args:
            case_id: Numeric case ID (or resource name; trailing segment is used).
            alert_identifier: Opaque ``alertGroupIdentifier`` or a plain alert
                id/name (auto-resolved).
            definition_identifier: Playbook UUID. Optional; resolved via the cards
                endpoint when not provided.

        Returns:
            Ordered list of executed :class:`PlaybookInstanceStep` records (may be
            empty if the run has not executed any steps yet).
        """
        run = self.get_alert_playbook_instance(
            case_id=case_id,
            alert_identifier=alert_identifier,
            definition_identifier=definition_identifier,
            should_fetch_steps=True,
        )
        return run.executed_path()


    def add_case_comment(self, case_id: Union[str, int], comment: str) -> CaseCommentRecord:
        """Executes the Add Case Comment workflow."""
        return self._add_case_comment_wf.execute(case_id=_normalize_case_id(case_id), comment=comment)

    def list_case_comments(self, case_id: Union[str, int]) -> List[CaseCommentRecord]:
        """Lists all analyst comments and AI assessment notes for a SOAR case (`case.list_comments`)."""
        return self._list_case_comments_wf.execute(case_id=_normalize_case_id(case_id))

    def get_case_wall(
        self,
        case_id: Union[str, int],
        limit: int = 50,
        page_token: Optional[str] = None,
        activity_type: Optional[str] = None,
    ) -> CaseWallResult:
        """Retrieves and parses the complete SOAR Case Activity Wall (`case.get_wall`)."""
        return self._get_case_wall_wf.execute(
            case_id=_normalize_case_id(case_id),
            limit=limit,
            page_token=page_token,
            activity_type=activity_type,
        )

    def attach_case_evidence(
        self,
        case_id: Union[str, int],
        evidence_items: List[Union[Dict[str, Any], str]],
        default_evidence_type: str = "EVIDENCE_TYPE_DETECTION",
    ) -> CaseEvidenceBatchResult:
        """Batch attaches evidence items (detections, events, alerts) to a SOAR Case."""
        return self._attach_case_evidence_wf.execute(
            case_id=_normalize_case_id(case_id),
            evidence_items=evidence_items,
            default_evidence_type=default_evidence_type,
        )

    def detach_case_evidence(
        self,
        case_id: Union[str, int],
        evidence_items: List[Union[Dict[str, Any], str]],
        default_evidence_type: str = "EVIDENCE_TYPE_DETECTION",
    ) -> CaseEvidenceBatchResult:
        """Batch detaches evidence items from a SOAR Case."""
        return self._detach_case_evidence_wf.execute(
            case_id=_normalize_case_id(case_id),
            evidence_items=evidence_items,
            default_evidence_type=default_evidence_type,
        )

    def attach_detections_to_case(
        self, case_id: Union[str, int], detection_ids: List[str]
    ) -> CaseEvidenceBatchResult:
        """Convenience method to attach non-alerting SIEM detections to a SOAR Case."""
        return self.attach_case_evidence(
            case_id=case_id,
            evidence_items=detection_ids,
            default_evidence_type="EVIDENCE_TYPE_DETECTION",
        )

    def attach_events_to_case(
        self, case_id: Union[str, int], event_ids: List[str]
    ) -> CaseEvidenceBatchResult:
        """Convenience method to attach individual UDM log events to a SOAR Case."""
        return self.attach_case_evidence(
            case_id=case_id,
            evidence_items=event_ids,
            default_evidence_type="EVIDENCE_TYPE_EVENT",
        )

    def correlate_silent_detections(
        self,
        case_id: Union[str, int],
        lookback_hours: int = 24,
        attach_to_case: bool = False,
        attach_entities: bool = True,
        post_wall_comment: bool = True,
        entity_filter: Optional[List[str]] = None,
        max_events: int = 1000,
    ) -> CaseDetectionCorrelationResult:
        """Correlates a SOAR case's involved entities with silent (non-alerting) detections in UDM."""
        return self._correlate_silent_detections_wf.execute(
            case_id=_normalize_case_id(case_id),
            lookback_hours=lookback_hours,
            attach_to_case=attach_to_case,
            attach_entities=attach_entities,
            post_wall_comment=post_wall_comment,
            entity_filter=entity_filter,
            max_events=max_events,
        )

    def add_case_alert_entity(
        self,
        case_id: Union[str, int],
        case_alert_id: Union[str, int],
        identifier: str,
        entity_type: str = "IP",
    ) -> Dict[str, Any]:
        """Manually attaches an involved entity to a specific case alert."""
        return self.adapter.add_case_alert_entity(
            case_id=str(case_id),
            case_alert_id=str(case_alert_id),
            identifier=identifier,
            entity_type=entity_type,
        )

    def search_unique_entities(
        self,
        filter_expr: Optional[str] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Searches or lists unique entities across the SecOps instance."""
        return self.adapter.search_unique_entities(
            filter_expr=filter_expr,
            page_size=page_size,
            page_token=page_token,
        )


    def update_case(
        self,
        case_id: Union[str, int],
        assignee: Optional[str] = None,
        stage: Optional[str] = None,
        incident: Optional[bool] = None,
        priority: Optional[str] = None,
        updates: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> CaseUpdateResult:
        """Executes the Update Case workflow."""
        return self._update_case_wf.execute(
            case_id=_normalize_case_id(case_id),
            assignee=assignee,
            stage=stage,
            incident=incident,
            priority=priority,
            updates=updates,
            update_mask=update_mask,
        )

    def assign_case(self, case_id: Union[str, int], assignee: str) -> CaseUpdateResult:
        """Executes the Assign Case workflow (to a role e.g. @Tier1 or user GUID/email)."""
        return self._assign_case_wf.execute(case_id=_normalize_case_id(case_id), assignee=assignee)

    def set_case_stage(self, case_id: Union[str, int], stage: str) -> CaseUpdateResult:
        """Executes the Set Case Stage workflow."""
        return self._set_case_stage_wf.execute(case_id=_normalize_case_id(case_id), stage=stage)

    def set_case_incident(self, case_id: Union[str, int], incident: bool = True) -> CaseUpdateResult:
        """Executes the Set Case Incident workflow."""
        return self._set_case_incident_wf.execute(case_id=_normalize_case_id(case_id), incident=incident)

    def update_case_alert(
        self,
        case_id: Union[str, int],
        alert_id: str,
        priority: Optional[str] = None,
        status: Optional[str] = None,
        updates: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> CaseAlertUpdateResult:
        """Executes the Update Case Alert workflow."""
        return self._update_case_alert_wf.execute(
            case_id=_normalize_case_id(case_id),
            alert_id=alert_id,
            priority=priority,
            status=status,
            updates=updates,
            update_mask=update_mask,
        )

    def set_case_alert_priority(self, case_id: Union[str, int], alert_id: str, priority: str) -> CaseAlertUpdateResult:
        """Executes the Set Case Alert Priority workflow."""
        return self._set_case_alert_priority_wf.execute(case_id=_normalize_case_id(case_id), alert_id=alert_id, priority=priority)

    def create_case_alert_recommendation(self, case_id: Union[str, int], alert_id: str) -> CaseAlertRecommendationJob:
        """Initiates async Gemini AI recommendation generation for a case alert."""
        return self._create_case_alert_recommendation_wf.execute(case_id=_normalize_case_id(case_id), alert_id=alert_id)

    def fetch_case_alert_recommendation(self, case_id: Union[str, int], recommendation_id: str) -> CaseAlertRecommendation:
        """Fetches a previously generated Gemini AI recommendation for a case alert."""
        return self._fetch_case_alert_recommendation_wf.execute(case_id=_normalize_case_id(case_id), recommendation_id=recommendation_id)

    def get_case_alert_recommendation(
        self,
        case_id: Union[str, int],
        alert_id: str,
        timeout_sec: float = 30.0,
        poll_interval_sec: float = 2.0,
    ) -> CaseAlertRecommendation:
        """Executes end-to-end Gemini AI recommendation generation and polls until complete."""
        return self._get_case_alert_recommendation_wf.execute(
            case_id=_normalize_case_id(case_id),
            alert_id=alert_id,
            timeout_sec=timeout_sec,
            poll_interval_sec=poll_interval_sec,
        )

    def get_or_create_case_summary(self, case_id: Union[str, int]) -> CaseSummary:
        """Gets or initiates generation of a Gemini AI summary for a SOAR case."""
        return self._get_or_create_case_summary_wf.execute(case_id=_normalize_case_id(case_id))

    def get_case_summary(
        self,
        case_id: Union[str, int],
        timeout_sec: float = 90.0,
        poll_interval_sec: float = 3.0,
    ) -> CaseSummary:
        """Requests a Gemini AI case summary and polls until complete or timeout."""
        return self._get_case_summary_wf.execute(
            case_id=_normalize_case_id(case_id),
            timeout_sec=timeout_sec,
            poll_interval_sec=poll_interval_sec,
        )

    def list_remediation_plans(
        self,
        case_id: Optional[Union[str, int]] = None,
        filter: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> RemediationPlanBatch:
        """Lists AI-generated agentic response / remediation plans for cases or alerts."""
        return self._list_remediation_plans_wf.execute(
            case_id=case_id,
            filter=filter,
            page_size=page_size,
            page_token=page_token,
        )

    def get_remediation_plan(self, plan_id: Union[str, int]) -> RemediationPlan:
        """Fetches a specific AI-generated agentic response / remediation plan by ID."""
        return self._get_remediation_plan_wf.execute(plan_id=str(plan_id))

    def get_agentic_response_plan(
        self,
        case_id: Optional[Union[str, int]] = None,
        plan_id: Optional[Union[str, int]] = None,
    ) -> Optional[RemediationPlan]:
        """Resolves an AI-generated agentic response plan by either case ID or plan ID."""
        return self._get_agentic_response_plan_wf.execute(case_id=case_id, plan_id=plan_id)

    def get_agentic_response_plans(
        self,
        case_id: Optional[Union[str, int]] = None,
        filter: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> RemediationPlanBatch:
        """Alias for list_remediation_plans."""
        return self.list_remediation_plans(
            case_id=case_id,
            filter=filter,
            page_size=page_size,
            page_token=page_token,
        )

    def list_remediation_actions(
        self,
        plan_id: Union[str, int],
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> List[RemediationAction]:
        """Lists actions belonging to an AI-generated remediation plan."""
        return self._list_remediation_actions_wf.execute(
            plan_id=plan_id,
            page_size=page_size,
            page_token=page_token,
        )

    def get_remediation_action(
        self,
        plan_id: Union[str, int],
        action_id: Union[str, int],
    ) -> RemediationAction:
        """Fetches an individual remediation action from a remediation plan."""
        return self._get_remediation_action_wf.execute(plan_id=plan_id, action_id=action_id)

    def list_tina_investigations(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = "start_time desc",
    ) -> TinaInvestigationBatch:
        """Lists Gemini TINA investigations with pagination and optional filtering."""
        return self._list_tina_investigations_wf.execute(
            page_size=page_size,
            page_token=page_token,
            filter=filter,
            order_by=order_by,
        )

    def get_tina_investigation(self, investigation_id: Union[str, int]) -> TinaInvestigation:
        """Retrieves a specific Gemini TINA investigation by ID or resource name."""
        return self._get_tina_investigation_wf.execute(investigation_id=str(investigation_id))

    def get_alert_latest_tina_investigation(self, alert_id: str) -> Optional[TinaInvestigation]:
        """Retrieves the latest Gemini TINA investigation for a specific alert ID."""
        return self._get_alert_latest_tina_investigation_wf.execute(alert_id=alert_id)


    def investigate_alert(self, alert_name: str) -> AlertInvestigation:
        """Executes the Alert Deep-Dive Investigation workflow."""
        return self._investigate_alert_wf.execute(alert_name=alert_name)

    def search_cases(
        self,
        query: Union[CaseSearchQuery, str] = "",
        start_time: Optional[Any] = None,
        end_time: Optional[Any] = None,
        tags: Optional[Union[List[str], str]] = None,
        priorities: Optional[Union[List[Union[str, CasePriority]], str, CasePriority]] = None,
        stages: Optional[Union[List[str], str]] = None,
        environments: Optional[Union[List[str], str]] = None,
        assigned_users: Optional[Union[List[str], str]] = None,
        is_important: Optional[bool] = None,
        page_size: int = 50,
        page_number: int = 0,
    ) -> CaseSearchBatch:
        """Executes the SOAR Case Search workflow.

        NOTE (SecOps nuance): the ``query`` string maps to the legacy ``title`` field,
        which is a *prefixed query DSL*, not a plain title-substring match. A bare term
        (e.g. a raw hash) will return zero results. Prefix the term using the closed
        vocabulary in :class:`CaseSearchPrefix` -- e.g. ``"Entity:<sha256>"``,
        ``"AlertName:<name>"``, ``"CaseIds:<id>"``, ``"TicketIds:<id>"``, ``"Port:<n>"``.
        For entity-driven lookups prefer :meth:`search_cases_by_entity`.
        """
        if isinstance(query, CaseSearchQuery):
            return self._search_cases_wf.execute(query)
        norm_priorities = [priorities] if isinstance(priorities, (str, CasePriority)) else (priorities or [])
        p_strings = [coerce_case_priority(p).value for p in norm_priorities]
        norm_tags = [tags] if isinstance(tags, str) else (tags or [])
        norm_stages = [stages] if isinstance(stages, str) else (stages or [])
        norm_envs = [environments] if isinstance(environments, str) else (environments or [])
        norm_users = [assigned_users] if isinstance(assigned_users, str) else (assigned_users or [])
        q = CaseSearchQuery(
            query_text=query,
            start_time=start_time,
            end_time=end_time,
            tags=norm_tags,
            priorities=p_strings,
            stages=norm_stages,
            environments=norm_envs,
            assigned_users=norm_users,
            is_important=is_important,
            page_size=page_size,
            page_number=page_number,
        )
        return self._search_cases_wf.execute(q)

    def search_cases_by_entity(
        self,
        entity_value: str,
        start_time: Optional[Any] = None,
        end_time: Optional[Any] = None,
        environments: Optional[Union[List[str], str]] = None,
        page_size: int = 50,
        page_number: int = 0,
    ) -> CaseSearchBatch:
        """Finds cases involving a given entity value (IP, hash, user, domain, etc.).

        Thin, discoverable wrapper over :meth:`search_cases` that applies the
        ``Entity:`` prefix required by the case-search DSL. This is the canonical
        "prior/similar cases by entity" lookup.

        Example::

            batch = engine.search_cases_by_entity(
                "2FDA6E766E1B5263D7D957F2FCC998C438BD92C7B7E566E6D31872C254FA88BB")
            print(batch.total_count)  # cases involving this file hash
        """
        return self.search_cases(
            query=CaseSearchPrefix.ENTITY.apply(entity_value),
            start_time=start_time,
            end_time=end_time,
            environments=environments,
            page_size=page_size,
            page_number=page_number,
        )

    def list_cases(
        self,
        status: Optional[Union[str, CaseStatus]] = None,
        environments: Optional[Union[List[str], str]] = None,
        priorities: Optional[Union[List[Union[str, CasePriority]], str, CasePriority]] = None,
        stages: Optional[Union[List[str], str]] = None,
        assignees: Optional[Union[List[str], str]] = None,
        is_important: Optional[bool] = None,
        is_incident: Optional[bool] = None,
        filter: Optional[str] = None,
        order_by: Optional[str] = "createTime desc",
        max_results: int = 1000,
        page_size: int = 1000,
    ) -> CaseListBatch:
        """Lists cases from the native cases collection with exact server-side filters.

        Prefer this over :meth:`search_cases` when you need an exact open/closed
        status filter or cases regardless of age: the legacy search has no status
        filter and is bounded by a time window, so long-lived open cases are
        invisible to it. Use :meth:`search_cases` for keyword / ``Entity:`` /
        ``AlertName:`` DSL queries and tag filters, which this endpoint lacks.

        Args:
            status: ``"OPENED"``/``"OPEN"``/``CaseStatus.OPEN`` or the CLOSED forms.
            environments, priorities, stages, assignees: one value or a list;
                values within a facet are OR-ed, facets are AND-ed. Priorities
                accept ``CasePriority``, ``"HIGH"`` or ``"PRIORITY_HIGH"``
                (``INFO`` is also valid server-side).
            is_important / is_incident: exact boolean filters.
            filter: raw server filter AND-ed with the typed facets, e.g.
                ``'createTime > 1791000000000'`` (epoch millis, unquoted).
            order_by: e.g. ``"createTime desc"`` (default), ``"updateTime desc"``,
                ``"priority desc"``; unknown fields raise HTTP 400.
            max_results: upper bound on cases fetched across pages.
            page_size: per-request size, 1..1000 (server maximum is 1000).

        Returns:
            :class:`CaseListBatch` with ``cases`` (:class:`CaseListItem`),
            ``total_count`` (server ``totalSize`` for the filter),
            ``next_page_token`` (set when ``max_results`` cut the listing short)
            and ``provenance``.

        Example::

            batch = engine.list_cases(status="OPENED", environments="Demoverse", max_results=5000)
            print(batch.total_count, len(batch.cases))
        """
        return self._list_cases_wf.execute(
            status=status,
            environments=environments,
            priorities=priorities,
            stages=stages,
            assignees=assignees,
            is_important=is_important,
            is_incident=is_incident,
            raw_filter=filter,
            order_by=order_by,
            max_results=max_results,
            page_size=page_size,
        )

    def triage_case(
        self,
        case_id: Union[str, int],
        fetch_summary: bool = True,
        search_precedents: bool = True,
        summary_timeout_sec: float = 15.0,
        apply_stage_update: bool = False,
        post_comment: bool = False,
    ) -> CaseTriageAssessment:
        """Executes full analyst triage workflow for a single specific case (`case.triage`).

        Runs deep case investigation (alerts, entities, comments), retrieves Gemini AI
        summary, performs historical title and entity precedent correlation, evaluates
        novelty vs repeat pattern, and optionally updates stage or posts triage audit comments.
        """
        cid = _normalize_case_id(case_id)
        return self._case_triage_wf.execute(
            case_id=cid,
            fetch_summary=fetch_summary,
            search_precedents=search_precedents,
            summary_timeout_sec=summary_timeout_sec,
            apply_stage_update=apply_stage_update,
            post_comment=post_comment,
        )

    def ai_investigate_case(
        self,
        case_id: Union[str, int],
        hunt_lookback_days: int = 14,
        hunt_receive_limit: int = 50,
        summary_timeout_sec: float = 90.0,
        escalate_incident: bool = False,
        escalate_alert_priority: Optional[str] = None,
        post_comment: bool = False,
        dry_run: bool = False,
    ) -> CaseAiInvestigationResult:
        """Executes deep autonomous AI investigation and UDM threat hunting on a case (`case.ai_investigate`).

        Fetches case workspace, polls Gemini AI summary, extracts network/user/file indicators,
        executes retrospective Chronicle UDM threat hunting across enterprise events, and
        optionally escalates incident status and posts a formatted investigation report.
        """
        cid = _normalize_case_id(case_id)
        return self._case_ai_investigate_wf.execute(
            case_id=cid,
            hunt_lookback_days=hunt_lookback_days,
            hunt_receive_limit=hunt_receive_limit,
            summary_timeout_sec=summary_timeout_sec,
            escalate_incident=escalate_incident,
            escalate_alert_priority=escalate_alert_priority,
            post_comment=post_comment,
            dry_run=dry_run,
        )

    def get_case_timeline(self, case_id: Union[str, int]) -> CaseTimeline:
        """Constructs a unified, chronologically sorted timeline of events and milestones in a case (`case.timeline`)."""
        cid = _normalize_case_id(case_id)
        return self._get_case_timeline_wf.execute(case_id=cid)

    def orchestrate_case_triage(
        self,
        case_ids: Optional[Union[List[Union[str, int]], str, int]] = None,
        limit: int = 5,
        open_only: bool = True,
        query_text: str = "",
        priorities: Optional[Union[List[Union[str, CasePriority]], str, CasePriority]] = None,
        stages: Optional[Union[List[str], str]] = None,
        tags: Optional[Union[List[str], str]] = None,
        environments: Optional[Union[List[str], str]] = None,
        assigned_users: Optional[Union[List[str], str]] = None,
        is_important: Optional[bool] = None,
        page_number: int = 0,
        search_precedents: bool = True,
        fetch_summary: bool = False,
    ) -> CaseTriageBatch:
        """Executes the Case Orchestrate Triage workflow (`case.orchestrate_triage`).

        Batched retrieval, parallel deep multi-resource investigation, precedent correlation,
        and automated triage scoring & subagent prompt synthesis for SOAR cases.
        """
        if case_ids is not None:
            if isinstance(case_ids, (str, int)):
                norm_case_ids = [_normalize_case_id(case_ids)]
            else:
                norm_case_ids = [_normalize_case_id(c) for c in case_ids]
        else:
            norm_case_ids = None

        norm_priorities = [priorities] if isinstance(priorities, (str, CasePriority)) else (priorities or [])
        p_strings = [coerce_case_priority(p).value for p in norm_priorities] if priorities is not None else None
        norm_tags = [tags] if isinstance(tags, str) else tags
        norm_stages = [stages] if isinstance(stages, str) else stages
        norm_envs = [environments] if isinstance(environments, str) else environments
        norm_users = [assigned_users] if isinstance(assigned_users, str) else assigned_users

        return self._orchestrate_case_triage_wf.execute(
            case_ids=norm_case_ids,
            limit=limit,
            open_only=open_only,
            query_text=query_text,
            priorities=p_strings,
            stages=norm_stages,
            tags=norm_tags,
            environments=norm_envs,
            assigned_users=norm_users,
            is_important=is_important,
            page_number=page_number,
            search_precedents=search_precedents,
            fetch_summary=fetch_summary,
        )

    def get_case_filter_values(
        self,
        filter_type: str,
        search_term: str = "",
        limit: int = 20,
    ) -> List[str]:
        """Retrieves facet filter suggestions for cases."""
        return self.adapter.get_case_filter_values(
            filter_type=filter_type,
            search_term=search_term,
            limit=limit,
        )

    def search_playbooks(
        self,
        query: Optional[Union[str, PlaybookSearchQuery]] = None,
        category: Optional[str] = None,
        is_enabled: Optional[bool] = None,
        playbook_type: Optional[Union[PlaybookType, str]] = None,
        environment: Optional[str] = None,
        limit: int = 100,
    ) -> PlaybookBatch:
        """Executes the SOAR Playbook Search & Filter workflow."""
        if isinstance(query, PlaybookSearchQuery):
            return self._search_playbooks_wf.execute(query)
        pb_type = coerce_playbook_type(playbook_type) if playbook_type is not None else None
        q = PlaybookSearchQuery(
            query=query,
            category=category,
            is_enabled=is_enabled,
            playbook_type=pb_type,
            environment=environment,
            limit=limit,
        )
        return self._search_playbooks_wf.execute(q)

    def get_playbook(self, identifier_or_id: str) -> PlaybookDetail:
        """Retrieves full playbook details, triggers, and execution steps."""
        return self._get_playbook_wf.execute(identifier_or_id=identifier_or_id)

    def list_playbook_categories(self) -> List[PlaybookCategory]:
        """Lists all SOAR Playbook categories/folders."""
        return self._list_playbook_cats_wf.execute()

    def save_playbook(
        self,
        playbook_payload: Dict[str, Any],
        category_name: Optional[str] = None,
        is_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Creates or updates a SOAR playbook or block workflow definition with automatic category ID/name synchronization."""
        return self._save_playbook_wf.execute(
            playbook_payload=playbook_payload,
            category_name=category_name,
            is_enabled=is_enabled,
        )

    def update_playbook_widget(
        self,
        identifier_or_id: str,
        html_content: str,
        step_name_or_id: Optional[str] = None,
        widget_title: Optional[str] = None,
        widget_index: Optional[int] = None,
        update_step_parameter: Optional[str] = None,
        update_step_parameter_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates an embedded HTML widget inside a SOAR Playbook's ViewsTemplates and saves the playbook."""
        return self._update_playbook_widget_wf.execute(
            identifier_or_id=identifier_or_id,
            html_content=html_content,
            step_name_or_id=step_name_or_id,
            widget_title=widget_title,
            widget_index=widget_index,
            update_step_parameter=update_step_parameter,
            update_step_parameter_value=update_step_parameter_value,
        )

    def delete_playbooks(
        self,
        identifiers_or_ids: Union[List[str], str],
    ) -> Dict[str, Any]:
        """Deletes one or more SOAR Playbooks by UUID identifier, numeric ID, or exact name."""
        norm_ids = [identifiers_or_ids] if isinstance(identifiers_or_ids, str) else list(identifiers_or_ids)
        return self._delete_playbooks_wf.execute(identifiers_or_ids=norm_ids)

    def export_playbooks(
        self,
        identifiers: Union[List[str], str],
    ) -> Dict[str, Any]:
        """Exports one or more SOAR playbooks into a portable package payload."""
        norm_ids = [identifiers] if isinstance(identifiers, str) else list(identifiers)
        return self.adapter.export_playbooks(norm_ids)

    def import_playbooks(
        self,
        blob_base64: str,
        import_as_duplicates: bool = False,
        environments_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Imports a base64-encoded SOAR playbook package payload."""
        return self.adapter.import_playbooks(
            blob_base64=blob_base64,
            import_as_duplicates=import_as_duplicates,
            environments_map=environments_map,
        )

    def audit_soar_playbook_health(
        self,
        days: int = 7,
        scan_deep: bool = True,
        fail_threshold_pct: float = 15.0,
        slow_threshold_minutes: float = 3.0,
    ) -> Dict[str, Any]:
        """Audits SOAR playbooks and modular blocks for configuration hygiene, failure spikes, faulted actions, and queue latency."""
        return self._audit_soar_playbook_health_wf.execute(
            days=days,
            scan_deep=scan_deep,
            fail_threshold_pct=fail_threshold_pct,
            slow_threshold_minutes=slow_threshold_minutes,
        )

    def audit_playbook_decay(
        self,
        workflow_identifier: Optional[str] = None,
        category: Optional[str] = None,
        lookback_days: int = 30,
        generate_brief: bool = True,
        persist: bool = True,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Audits SOAR playbooks and modular nested blocks for 100-pt static resilience, 30-day telemetry, and decay."""
        return self._audit_playbook_decay_wf.execute(
            workflow_identifier=workflow_identifier,
            category=category,
            lookback_days=lookback_days,
            generate_brief=generate_brief,
            persist=persist,
            limit=limit,
        )

    def audit_timestamp_integrity(
        self,
        days: int = 7,
        clear_cache: bool = True,
        project_id: Optional[str] = None,
        persist: bool = True,
    ) -> TimestampIntegrityReport:
        """Audits log sources for ingestion latency bottlenecks and NTP clock skews.

        ``persist=False`` skips the Evidence Fabric write (read-only run). Writes
        only happen when the engine was constructed with an ``evidence_store``.
        """
        return self._timestamp_integrity_wf.execute(
            days=days,
            clear_cache=clear_cache,
            project_id=project_id,
            persist=persist,
        )

    def get_latest_timestamp_integrity(self) -> Optional[Dict[str, Any]]:
        """Retrieves the latest stored timestamp integrity report from Evidence Fabric (read-only).

        Returns None when no evidence store is wired or no report has been stored.
        """
        if not self.evidence_store:
            return None
        return self.evidence_store.get_latest_timestamp_integrity()

    def search_integrations(
        self,
        query: Optional[Union[str, IntegrationSearchQuery]] = None,
        environment: Optional[str] = None,
        is_configured: Optional[bool] = None,
        is_certified: Optional[bool] = None,
        limit: int = 100,
    ) -> IntegrationBatch:
        """Executes the SOAR Integration Search & Filter workflow."""
        if isinstance(query, IntegrationSearchQuery):
            return self._search_integrations_wf.execute(query)
        q = IntegrationSearchQuery(
            query=query,
            environment=environment,
            is_configured=is_configured,
            is_certified=is_certified,
            limit=limit,
        )
        return self._search_integrations_wf.execute(q)

    def get_integration(self, identifier: str) -> IntegrationDetail:
        """Retrieves complete details for a specific integration with instances and documentation."""
        return self._get_integration_wf.execute(identifier=identifier)

    def list_integration_instances(
        self,
        integration_id: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> List[IntegrationInstance]:
        """Lists configured integration instances across environments or for a specific integration."""
        return self._list_integration_instances_wf.execute(
            integration_id=integration_id,
            environment=environment,
        )

    def get_integration_instance_affected_items(
        self,
        integration_id: str,
        instance_id: str,
    ) -> IntegrationInstanceAffectedItems:
        """Retrieves downstream playbooks and items affected by an integration instance."""
        return self._get_integration_instance_affected_items_wf.execute(
            integration_id=integration_id,
            instance_id=instance_id,
        )

    def delete_integration_instance(
        self,
        integration_id: str,
        instance_id: str,
        force: bool = False,
    ) -> IntegrationInstanceDeleteResult:
        """Deletes a configured integration instance with pre-flight dependency guard."""
        return self._delete_integration_instance_wf.execute(
            integration_id=integration_id,
            instance_id=instance_id,
            force=force,
        )


    def list_remote_agents(
        self,
        state_filter: Optional[str] = None,
    ) -> List[RemoteAgent]:
        """Lists remote proxy execution agents."""
        return self._list_remote_agents_wf.execute(state_filter=state_filter)

    def search_jobs(
        self,
        query: Optional[Union[str, JobSearchQuery]] = None,
        integration: Optional[str] = None,
        enabled: Optional[bool] = None,
        limit: int = 100,
    ) -> JobBatch:
        """Executes the SOAR Scheduled Jobs Search & Filter workflow."""
        if isinstance(query, JobSearchQuery):
            return self._search_jobs_wf.execute(query)
        q = JobSearchQuery(
            query=query,
            integration=integration,
            enabled=enabled,
            limit=limit,
        )
        return self._search_jobs_wf.execute(q)

    def get_job(
        self,
        integration: str,
        job_id: str,
    ) -> JobDetail:
        """Retrieves complete details for a specific SOAR job with instances and logs."""
        return self._get_job_wf.execute(
            integration=integration,
            job_id=job_id,
        )

    def list_job_instances(
        self,
        integration: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> List[JobInstance]:
        """Lists runtime job instances across environments or for a specific job."""
        return self._list_job_instances_wf.execute(
            integration=integration,
            job_id=job_id,
        )

    def get_job_instance_logs(
        self,
        job_instance_id: str,
        limit: int = 20,
        order_by: str = "endTime desc",
    ) -> List[JobExecutionLog]:
        """Retrieves execution run records and text logs for a specific job instance."""
        return self._get_job_instance_logs_wf.execute(
            job_instance_id=job_instance_id,
            limit=limit,
            order_by=order_by,
        )

    def update_job(
        self,
        integration: str,
        job_id: str,
        script: Optional[str] = None,
        description: Optional[str] = None,
        enabled: Optional[bool] = None,
        parameters: Optional[List[Dict[str, Any]]] = None,
        update_mask: Optional[str] = None,
        sync_instances: bool = True,
    ) -> Dict[str, Any]:
        """Updates a SOAR scheduled job definition and optionally syncs script changes to its active job instances."""
        return self._update_job_wf.execute(
            integration=integration,
            job_id=job_id,
            script=script,
            description=description,
            enabled=enabled,
            parameters=parameters,
            update_mask=update_mask,
            sync_instances=sync_instances,
        )

    def update_job_instance(
        self,
        integration: str,
        job_id: str,
        instance_id: str,
        script: Optional[str] = None,
        enabled: Optional[bool] = None,
        interval_seconds: Optional[int] = None,
        parameters: Optional[List[Dict[str, Any]]] = None,
        advanced_config: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates a configured runtime SOAR job instance (script, schedule, parameters, or enabled status)."""
        return self._update_job_instance_wf.execute(
            integration=integration,
            job_id=job_id,
            instance_id=instance_id,
            script=script,
            enabled=enabled,
            interval_seconds=interval_seconds,
            parameters=parameters,
            advanced_config=advanced_config,
            update_mask=update_mask,
        )

    def create_job_instance(
        self,
        integration: str,
        job_id: str,
        instance_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Creates a new scheduled runtime SOAR job instance under a job definition."""
        return self._create_job_instance_wf.execute(
            integration=integration,
            job_id=job_id,
            instance_payload=instance_payload,
        )

    def search_content_packs(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        pack_type: Optional[str] = None,
        deployed: Optional[bool] = None,
        limit: int = 100,
    ) -> ContentPackBatch:
        """Searches and filters Content Hub Marketplace Content Packs."""
        q = ContentPackSearchQuery(
            query=query,
            category=category,
            pack_type=pack_type,
            deployed=deployed,
            limit=limit,
        )
        return self._search_content_packs_wf.execute(q)

    def get_content_pack(
        self,
        pack_id_or_title: str,
    ) -> ContentPackDetail:
        """Retrieves a complete Content Pack composite with bundled components."""
        return self._get_content_pack_wf.execute(pack_id_or_title)

    def list_content_pack_categories(self) -> List[Dict[str, Any]]:
        """Discovers and aggregates distinct Content Hub categories with pack counts."""
        return self._list_content_pack_cats_wf.execute()

    def search_curated_rulesets(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        log_source: Optional[str] = None,
        limit: int = 50,
    ) -> CuratedRuleSetBatch:
        """Discovers and searches Google SecOps Curated Rule Sets."""
        q = CuratedRuleSearchQuery(
            query=query,
            category=category,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            log_source=log_source,
            limit=limit,
        )
        return self._search_curated_rulesets_wf.execute(q)

    def list_curated_rule_set_deployments(
        self,
        include_display_names: bool = True,
        page_size: int = 1000,
        max_results: Optional[int] = None,
    ) -> CuratedRuleSetDeploymentListResult:
        """Lists every curated rule set precision deployment (all pages, one bulk endpoint).

        Records: ``rule_set_id``, ``category_id``, ``precision`` (BROAD/PRECISE),
        ``enabled``, ``alerting``, ``display_name`` (joined from the rule set
        catalog when ``include_display_names``), ``resource_name``, ``raw``.
        """
        return self._list_curated_rule_set_deployments_wf.execute(
            include_display_names=include_display_names,
            page_size=page_size,
            max_results=max_results,
        )

    def list_curated_rulesets(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
        category_id: Optional[str] = None,
    ) -> CuratedRuleSetListResult:
        """Lists Curated Rule Sets (single page by default; ``all_pages=True`` for every page)."""
        return self._list_curated_rulesets_wf.execute(
            page_size=page_size,
            page_token=page_token,
            all_pages=all_pages,
            max_results=max_results,
            category_id=category_id,
        )

    def list_curated_rules(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> CuratedRuleListResult:
        """Lists individual curated rules (single page by default; slow, ~20 s per page)."""
        return self._list_curated_rules_wf.execute(
            page_size=page_size,
            page_token=page_token,
            all_pages=all_pages,
            max_results=max_results,
        )

    def get_curated_ruleset(
        self,
        ruleset_id_or_title: str,
        include_rules: bool = True,
        include_detection_count: bool = True,
    ) -> CuratedRuleSetDetail:
        """Deep-inspects a Curated Rule Set, its deployments, member rules, and detection telemetry.

        IDs and resource names are fetched directly; titles must match exactly
        or be a unique substring (ambiguity raises). ``include_rules=False``
        skips the slow member-rule catalog scan.
        """
        return self._get_curated_ruleset_wf.execute(
            ruleset_id_or_title,
            include_rules=include_rules,
            include_detection_count=include_detection_count,
        )

    def get_curated_rule(
        self,
        rule_id_or_title: str,
    ) -> CuratedRuleDetail:
        """Retrieves a Curated Rule, its metadata, and its executable YARA-L logic."""
        return self._get_curated_rule_wf.execute(rule_id_or_title)

    def get_curated_detection_metrics(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> CuratedDetectionMetrics:
        """Aggregates detection firing counts and retrieves tenant rule engine quotas."""
        return self._get_curated_metrics_wf.execute(start_time=start_time, end_time=end_time)

    def set_curated_ruleset_deployment(
        self,
        ruleset_id_or_title: str,
        precision: str = "PRECISE",
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        sync_rules: bool = True,
    ) -> CuratedRuleSetDeployment:
        """Updates enabled and alerting states for a Curated Rule Set precision deployment."""
        return self._set_curated_ruleset_deployment_wf.execute(
            ruleset_id_or_title=ruleset_id_or_title,
            precision=precision,
            enabled=enabled,
            alerting=alerting,
            sync_rules=sync_rules,
        )

    def audit_curated_detections_health(
        self,
        days: int = 7,
        scan_deployments: bool = True,
    ) -> CuratedDetectionHealthReport:
        """Performs a comprehensive health check and misconfiguration audit across Curated Detections."""
        from runbooks.operations.curated_detections_health import generate_curated_detections_health_report
        return generate_curated_detections_health_report(
            engine=self,
            days=days,
            scan_deployments=scan_deployments,
        )

    # --- Detection Tuning & UDM Findings Refinements Methods ---

    def list_findings_refinements(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> FindingsRefinementBatch:
        """Lists active tenant UDM findings refinements and detection exclusions."""
        return self._manage_findings_refinements_wf.list_refinements(
            page_size=page_size,
            page_token=page_token,
            all_pages=all_pages,
            max_results=max_results,
        )

    def create_findings_refinement(
        self,
        display_name: str,
        query: str,
        curated_rule_ids: Optional[Union[List[str], str]] = None,
    ) -> FindingsRefinementSummary:
        """Creates a new UDM findings refinement exclusion for curated rules or tenant-wide detections."""
        return self._manage_findings_refinements_wf.create_refinement(
            display_name=display_name,
            query=query,
            curated_rule_ids=parse_id_list(curated_rule_ids, "curated_rule_ids") or None,
        )

    def delete_findings_refinement(
        self,
        refinement_id: str,
    ) -> Dict[str, Any]:
        """Removes an active UDM findings refinement exclusion."""
        return self._manage_findings_refinements_wf.delete_refinement(refinement_id)

    def test_findings_refinement(
        self,
        curated_rule_ids: Union[List[str], str],
        query: str,
        lookback_days: int = 14,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> FindingsRefinementTestResult:
        """Simulates and dry-runs an exclusion query against historical detections to compute noise suppression ratio."""
        return self._test_findings_refinement_wf.execute(
            curated_rule_ids=parse_id_list(curated_rule_ids, "curated_rule_ids"),
            query=query,
            lookback_days=lookback_days,
            start_time=start_time,
            end_time=end_time,
        )

    def find_top_noisy_rules(
        self,
        lookback_days: int = 7,
        alert_state: str = "ALL",
        limit: int = 20,
    ) -> NoisyRulesBatch:
        """Aggregates and ranks top firing detection rules with alert state, volume, and Google vs Customer rule classification."""
        return self._find_top_noisy_rules_wf.execute(
            lookback_days=lookback_days,
            alert_state=alert_state,
            limit=limit,
        )

    def analyze_entity_cardinality(
        self,
        rule_id: str,
        dimensions: Optional[Union[List[str], str]] = None,
        lookback_days: int = 14,
        limit_per_dimension: int = 10,
    ) -> EntityCardinalityReport:
        """Profiles multi-dimensional entity subfield distributions (IPs, hostnames, users, processes, DNS) for a detection rule."""
        norm_dims = [dimensions] if isinstance(dimensions, str) else dimensions
        return self._analyze_entity_cardinality_wf.execute(
            rule_id=rule_id,
            dimensions=norm_dims,
            lookback_days=lookback_days,
            limit_per_dimension=limit_per_dimension,
        )

    def cross_reference_rule_cases(
        self,
        rule_id: str,
        lookback_days: int = 90,
        limit: int = 20,
        environment: Optional[str] = None,
    ) -> RuleCaseHistoryBatch:
        """Cross-references historical SOAR cases associated with a detection rule to extract analyst resolutions and root causes.

        Records include ``environment`` and the numeric ``soar_case_id``;
        ``environment`` filters by exact SOAR environment name.
        """
        return self._cross_reference_rule_cases_wf.execute(
            rule_id=rule_id,
            lookback_days=lookback_days,
            limit=limit,
            environment=environment,
        )

    def get_rule_case_environments(self, lookback_days: int = 30) -> RuleCaseEnvironmentResult:
        """Rule -> SOAR environment join: distinct cases per (rule_id, environment).

        Pairs carry ``rule_id``, ``rule_name``, ``environment``, ``case_count``.
        One dashboard query (~15-20 s for 30 days). Raises on query error.
        """
        return self._rule_case_environments_wf.execute(lookback_days=lookback_days)

    def tune_detection(
        self,
        rule_id: str,
        lookback_days: int = 7,
    ) -> DetectionTuningReport:
        """End-to-end autonomous workflow that analyzes noisy rules, profiles cardinality, cross-references SOAR cases, formulates exclusions, and dry-run tests suppression."""
        return self._diagnose_and_tune_detection_wf.execute(
            rule_id=rule_id,
            lookback_days=lookback_days,
        )

    def sample_detection_events(
        self,
        rule_id: str,
        lookback_days: int = 14,
        limit: int = 20,
    ) -> CorrelatedSamplingBatch:
        """Pulls correlated multi-attribute detection tuples (user + command + host + IP) from detection collection elements."""
        return self._sample_detection_events_wf.execute(
            rule_id=rule_id,
            lookback_days=lookback_days,
            limit=limit,
        )

    def synthesize_detection_tuning(
        self,
        rule_id: str,
        lookback_days: int = 14,
        dominance_threshold: float = 0.20,
    ) -> DetectionTuningProposal:
        """Synthesizes safe multi-factor exclusions enforcing HITL safety guardrails, compiles candidate rule patches or UDM refinements, and calculates noise reduction projections."""
        return self._synthesize_tuning_proposal_wf.execute(
            rule_id=rule_id,
            lookback_days=lookback_days,
            dominance_threshold=dominance_threshold,
        )

    # --- Milestone 5.8: Content Hub Marketplace Response Integrations Methods ---

    def search_marketplace_integrations(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        installed: Optional[bool] = None,
        update_available: Optional[bool] = None,
        certified: Optional[bool] = None,
        limit: int = 50,
    ) -> MarketplaceIntegrationBatch:
        """Discovers, searches, and filters Marketplace Response Integrations."""
        q = MarketplaceIntegrationSearchQuery(
            query=query,
            category=category,
            installed=installed,
            update_available=update_available,
            certified=certified,
            limit=limit,
        )
        return self._search_marketplace_integrations_wf.execute(q)

    def get_marketplace_integration(
        self,
        identifier_or_title: str,
    ) -> MarketplaceIntegrationDetail:
        """Retrieves full details for a Marketplace Response Integration."""
        return self._get_marketplace_integration_wf.execute(identifier_or_title)

    def get_marketplace_integration_diff(
        self,
        identifier_or_title: str,
    ) -> MarketplaceCommercialDiff:
        """Retrieves commercial version diff comparing installed vs latest marketplace version."""
        return self._get_marketplace_integration_diff_wf.execute(identifier_or_title)

    def get_marketplace_integration_affected_items(
        self,
        identifier_or_title: str,
    ) -> MarketplaceAffectedItems:
        """Retrieves downstream environment instances and playbooks affected by an integration."""
        return self._get_marketplace_affected_items_wf.execute(identifier_or_title)

    def search_dashboards(
        self,
        query: Optional[str] = None,
        dashboard_type: Optional[str] = None,
        limit: int = 50,
    ) -> DashboardBatch:
        """Discovers and filters native dashboards."""
        q = DashboardSearchQuery(query=query, dashboard_type=dashboard_type, limit=limit)
        return self._search_dashboards_wf.execute(q)

    def get_dashboard(
        self,
        identifier_or_title: str,
        include_queries: bool = True,
    ) -> DashboardDetail:
        """Retrieves complete composite dashboard graph with charts and queries."""
        return self._get_dashboard_wf.execute(identifier_or_title, include_queries=include_queries)

    def create_dashboard(
        self,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
        filters: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
    ) -> DashboardSummary:
        """Creates a new Native Dashboard in Google SecOps."""
        return self._create_dashboard_wf.execute(
            display_name=display_name,
            description=description,
            dashboard_type=dashboard_type,
            filters=filters,
            charts=charts,
        )

    def update_dashboard(
        self,
        dashboard_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        charts: Optional[List[Dict[str, Any]]] = None,
        update_mask: Optional[str] = None,
    ) -> DashboardSummary:
        """Updates an existing Native Dashboard's display name, description, filters, or chart layouts."""
        return self._update_dashboard_wf.execute(
            dashboard_id=dashboard_id,
            display_name=display_name,
            description=description,
            filters=filters,
            charts=charts,
            update_mask=update_mask,
        )

    def delete_dashboard(self, dashboard_id: str) -> Dict[str, Any]:
        """Deletes a Native Dashboard by ID."""
        return self._delete_dashboard_wf.execute(dashboard_id=dashboard_id)

    def duplicate_dashboard(
        self,
        dashboard_id: str,
        display_name: str,
        description: Optional[str] = None,
        dashboard_type: str = "CUSTOM",
    ) -> DashboardSummary:
        """Duplicates an existing Native Dashboard under a new display name."""
        return self._duplicate_dashboard_wf.execute(
            dashboard_id=dashboard_id,
            display_name=display_name,
            description=description,
            dashboard_type=dashboard_type,
        )

    def add_dashboard_chart(
        self,
        dashboard_id: str,
        display_name: str,
        query: Optional[str] = None,
        description: Optional[str] = None,
        tile_type: str = "TILE_TYPE_VISUALIZATION",
        visualization: Optional[Dict[str, Any]] = None,
        data_sources: Optional[List[str]] = None,
        time_unit: str = "DAY",
        time_value: str = "1",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        span_x: int = 6,
        span_y: int = 4,
        start_x: int = 0,
        start_y: int = 0,
        drill_down_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Adds a chart widget (visualization, markdown, or button) and optional query to a Native Dashboard."""
        return self._add_dashboard_chart_wf.execute(
            dashboard_id=dashboard_id,
            display_name=display_name,
            query=query,
            description=description,
            tile_type=tile_type,
            visualization=visualization,
            data_sources=data_sources,
            time_unit=time_unit,
            time_value=time_value,
            start_time=start_time,
            end_time=end_time,
            span_x=span_x,
            span_y=span_y,
            start_x=start_x,
            start_y=start_y,
            drill_down_config=drill_down_config,
        )

    def update_dashboard_chart(
        self,
        chart_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        visualization: Optional[Dict[str, Any]] = None,
        data_sources: Optional[List[str]] = None,
        drill_down_config: Optional[Dict[str, Any]] = None,
        query_id: Optional[str] = None,
        query: Optional[str] = None,
        time_unit: Optional[str] = None,
        time_value: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Updates an existing DashboardChart and/or its associated DashboardQuery."""
        return self._update_dashboard_chart_wf.execute(
            chart_id=chart_id,
            display_name=display_name,
            description=description,
            visualization=visualization,
            data_sources=data_sources,
            drill_down_config=drill_down_config,
            query_id=query_id,
            query=query,
            time_unit=time_unit,
            time_value=time_value,
            start_time=start_time,
            end_time=end_time,
        )

    def remove_dashboard_chart(self, dashboard_id: str, chart_id: str) -> Dict[str, Any]:
        """Removes a chart from a Native Dashboard."""
        return self._remove_dashboard_chart_wf.execute(dashboard_id=dashboard_id, chart_id=chart_id)

    def execute_dashboard_query(
        self,
        query_name_or_id: Optional[str] = None,
        query_text: Optional[str] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        use_previous_time_range: bool = False,
        query_source: str = "DASHBOARD",
        time_unit: str = "DAY",
        time_value: str = "1",
        dialect: str = "YL2",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        clear_cache: Optional[bool] = None,
    ) -> DashboardQueryResult:
        """Executes a dashboard query (by resource ID or inline query expression) and normalizes columnar output into tabular rows."""
        return self._execute_dashboard_query_wf.execute(
            query_name_or_id=query_name_or_id,
            query_text=query_text,
            filters=filters,
            use_previous_time_range=use_previous_time_range,
            query_source=query_source,
            time_unit=time_unit,
            time_value=time_value,
            dialect=dialect,
            start_time=start_time,
            end_time=end_time,
            clear_cache=clear_cache,
        )

    def validate_dashboard_query(
        self,
        raw_query: str,
        dialect: str = "DIALECT_STATS",
    ) -> ValidationResult:
        """Validates statistical query syntax."""
        return self._validate_dashboard_query_wf.execute(raw_query=raw_query, dialect=dialect)


    def run_dashboard_health_check(
        self,
        dashboard_name: str,
    ) -> DashboardHealthCheckResult:
        """Executes comprehensive health check for a named dashboard.
        
        Workflow retrieves dashboard configuration, executes all widget queries,
        and generates operational summary of ingestion health metrics.
        
        Args:
            dashboard_name: Display name of dashboard (e.g., "Data Ingestion and Health")
        
        Returns:
            DashboardHealthCheckResult containing dashboard_id, query_results, summary, and errors
        """
        return run_dashboard_health_check(
            adapter=self.adapter,
            dashboard_name=dashboard_name,
            project_id=None,  # Use adapter defaults
            customer_id=None,
            region=None,
        )

    def audit_dashboard_health(
        self,
        lookback_days: int = 14,
        stale_days: int = 180,
        validate_queries: bool = True,
        max_deep_dashboards: int = 50,
    ) -> DashboardHealthReport:
        """Audits native dashboards for creations, modifications, broken widget queries, and staleness."""
        return self._audit_dashboard_health_wf.execute(
            lookback_days=lookback_days,
            stale_days=stale_days,
            validate_queries=validate_queries,
            max_deep_dashboards=max_deep_dashboards,
        )

    def get_managed_domain_settings(self) -> ManagedDomainSettings:
        """Retrieves approved email domains configured for report deliveries and alerts."""
        return self._get_managed_domains_wf.execute()

    def search_feeds(
        self,
        query: Optional[str] = None,
        feed_source_type: Optional[str] = None,
        log_type: Optional[str] = None,
        state: Optional[str] = None,
        limit: int = 50,
    ) -> FeedBatch:
        """Searches, lists, and filters push/pull ingestion feeds."""
        return self._search_feeds_wf.execute(
            query=query,
            feed_source_type=feed_source_type,
            log_type=log_type,
            state=state,
            limit=limit,
        )

    def get_feed(self, identifier_or_title: str) -> FeedDetail:
        """Retrieves complete configuration details for a specific ingestion feed."""
        return self._get_feed_wf.execute(identifier_or_title)

    def audit_feed_health(self, lookback_days: int = 7) -> FeedHealthReport:
        """Audits all configured ingestion feeds against Health Hub telemetry and decay indicators."""
        return self._audit_feed_health_wf.execute(lookback_days=lookback_days)

    def search_log_processing_pipelines(
        self,
        query: Optional[str] = None,
        log_type: Optional[str] = None,
        limit: int = 50,
    ) -> LogProcessingPipelineBatch:
        """Discovers and lists Data Processing Pipelines."""
        return self._search_pipelines_wf.execute(
            query=query,
            log_type=log_type,
            limit=limit,
        )

    def get_log_processing_pipeline(self, identifier_or_title: str) -> LogProcessingPipelineDetail:
        """Retrieves full transform statements and Bindplane link for a Data Processing Pipeline."""
        return self._get_pipeline_wf.execute(identifier_or_title)

    def list_feed_source_type_schemas(self, limit: int = 100) -> FeedSourceTypeBatch:
        """Lists all supported feed source types and metadata."""
        return self._list_feed_source_types_wf.execute(limit=limit)

    def list_feed_log_type_schemas(
        self,
        feed_source_type: str,
        limit: int = 100,
        include_field_schemas: bool = False,
    ) -> FeedLogTypeBatch:
        """Lists log type schemas for a feed source type, with lean payload handling."""
        return self._list_feed_log_types_wf.execute(
            feed_source_type=feed_source_type,
            limit=limit,
            include_field_schemas=include_field_schemas,
        )

    # --------------------------------------------------------------------------
    # Milestone 5.11: SIEM Settings - Parsers, Log Types, Extensions & Settings
    # --------------------------------------------------------------------------

    def list_log_types(self, query: str = "", limit: int = 100) -> LogTypeBatch:
        """Discovers and filters supported ingestion log types."""
        return self._list_log_types_wf.execute(query=query, limit=limit)

    def get_log_type_display_name(self, log_type_id: str) -> Optional[str]:
        """Deterministically resolves an internal log_type ID (e.g. 'GCP_IDS', 'PAN_FIREWALL') to its official display name."""
        batch = self._list_log_types_wf.execute(query=log_type_id, limit=50)
        target = log_type_id.strip().upper()
        for lt in batch.log_types:
            if lt.id.upper() == target:
                return lt.display_name
        return None

    def search_parsers(
        self,
        log_type: str = "-",
        creator: str = "ALL",
        state: str = "ALL",
        query: str = "",
        limit: int = 50,
    ) -> ParserBatch:
        """Discovers and filters parsers across log types."""
        return self._search_parsers_wf.execute(
            log_type=log_type,
            creator=creator,
            state=state,
            query=query,
            limit=limit,
        )

    def get_parser(self, log_type: str, parser_id: Optional[str] = None) -> ParserDetail:
        """Retrieves full parser metadata and decodes CBN Logstash filter code."""
        return self._get_parser_wf.execute(log_type=log_type, parser_id=parser_id)

    def run_parser(
        self,
        log_type: str,
        raw_log_text: str,
        parser_cbn: Optional[str] = None,
    ) -> ParserRunResult:
        """Executes a Logstash CBN parser configuration against a raw log string."""
        return self._run_parser_wf.execute(
            log_type=log_type,
            raw_log_text=raw_log_text,
            parser_cbn=parser_cbn,
        )

    def diagnose_unparsed_logs(
        self,
        log_type: str,
        lookback_hours: int = 168,
        limit: int = 5,
    ) -> UnparsedLogsDiagnosticBatch:
        """Finds unparsed raw logs for a log type and runs them against the active parser to diagnose errors."""
        return self._diagnose_unparsed_wf.execute(
            log_type=log_type,
            lookback_hours=lookback_hours,
            limit=limit,
        )

    def search_parser_extensions(
        self,
        log_type: str = "-",
        query: str = "",
        limit: int = 50,
    ) -> ParserExtensionBatch:
        """Discovers parser extensions across log types."""
        return self._search_parser_extensions_wf.execute(
            log_type=log_type,
            query=query,
            limit=limit,
        )

    def get_parser_extension(self, log_type: str, extension_id: str) -> ParserExtensionDetail:
        """Retrieves full parser extension configuration, decoded snippet, and test log."""
        return self._get_parser_extension_wf.execute(log_type=log_type, extension_id=extension_id)

    def get_log_type_setting(self, log_type: str) -> LogTypeSetting:
        """Retrieves autonomous parsing settings for a log type."""
        return self._get_log_type_setting_wf.execute(log_type=log_type)

    def audit_parser_health(self, lookback_days: int = 7) -> ParserHealthReport:
        """Audits all configured SIEM parsers and extensions against Health Hub telemetry and version drift."""
        return self._audit_parser_health_wf.execute(lookback_days=lookback_days)

    # --------------------------------------------------------------------------
    # Milestone 5.12: SIEM Settings - Preview Features & Data RBAC
    # --------------------------------------------------------------------------

    def list_preview_features(
        self,
        enabled_only: bool = False,
        query: str = "",
        limit: int = 100,
    ) -> PreviewFeatureBatch:
        """Discovers and filters customer preview features."""
        return self._list_preview_features_wf.execute(
            enabled_only=enabled_only,
            query=query,
            limit=limit,
        )

    def get_preview_feature(self, feature_id: str) -> PreviewFeatureSummary:
        """Retrieves detailed configuration and status for a preview feature."""
        return self._get_preview_feature_wf.execute(feature_id=feature_id)

    def search_data_access_scopes(
        self,
        query: str = "",
        limit: int = 100,
    ) -> DataAccessScopeBatch:
        """Discovers and filters Data Access Scopes."""
        return self._search_data_access_scopes_wf.execute(query=query, limit=limit)

    def get_data_access_scope(self, scope_id: str) -> DataAccessScopeDetail:
        """Retrieves deep configuration of a Data Access Scope."""
        return self._get_data_access_scope_wf.execute(scope_id=scope_id)

    def search_data_access_labels(
        self,
        query: str = "",
        limit: int = 100,
    ) -> DataAccessLabelBatch:
        """Discovers and filters Data Access Labels."""
        return self._search_data_access_labels_wf.execute(query=query, limit=limit)

    def get_data_access_label(self, label_id: str) -> DataAccessLabelDetail:
        """Retrieves deep configuration of a Data Access Label."""
        return self._get_data_access_label_wf.execute(label_id=label_id)

    def search_environment_scopes(
        self,
        query: str = "",
        limit: int = 100,
    ) -> EnvironmentScopeBatch:
        """Discovers SOAR environments and inspects bound Data Access Scopes."""
        return self._search_environment_scopes_wf.execute(query=query, limit=limit)

    def list_enrichment_combinations(
        self,
        enrichment_type: str = "ALL",
        target_log_type: str = "",
        limit: int = 100,
    ) -> EnrichmentCombinationBatch:
        """Discovers available entity enrichment combinations."""
        return self._list_enrichment_combinations_wf.execute(
            enrichment_type=enrichment_type,
            target_log_type=target_log_type,
            limit=limit,
        )

    def search_enrichment_controls(
        self,
        query: str = "",
        enrichment_type: str = "ALL",
        limit: int = 100,
    ) -> EnrichmentControlBatch:
        """Discovers and filters deployed enrichment controls."""
        return self._search_enrichment_controls_wf.execute(
            query=query,
            enrichment_type=enrichment_type,
            limit=limit,
        )

    def get_enrichment_control(self, control_id: str) -> EnrichmentControlDetail:
        """Retrieves deep configuration of a deployed enrichment control."""
        return self._get_enrichment_control_wf.execute(control_id=control_id)

    def get_agent_settings(self) -> GeminiAgentSettings:
        """Retrieves Gemini Triage & Investigation Agent settings."""
        return self._get_agent_settings_wf.execute()

    def get_entity_risk_config(self) -> EntityRiskConfig:
        """Retrieves UEBA entity risk scoring configuration."""
        return self._get_entity_risk_config_wf.execute()

    def get_tenant_instance(self) -> TenantInstanceDetails:
        """Retrieves root tenant instance details and configuration flags."""
        return self._get_tenant_instance_wf.execute()

    def audit_tenant_posture(self) -> Dict[str, Any]:
        """Audits complete tenant configuration posture across SIEM, SOAR, RBAC, and topography."""
        from runbooks.operations.tenant_settings_audit import generate_tenant_settings_report
        return generate_tenant_settings_report(self)

    # --- Milestone 6.1: SOAR Settings & Case Data Configuration ---

    def search_soar_users(
        self,
        query: str = "",
        role_filter: Optional[int] = None,
        limit: int = 100,
    ) -> SoarUserBatch:
        """Searches and filters SOAR users and external identity profiles."""
        return self._search_soar_users_wf.execute(
            query=query,
            role_filter=role_filter,
            limit=limit,
        )

    def get_soar_user(self, user_id: str) -> SoarUserDetail:
        """Retrieves deep inspection of a single SOAR user."""
        return self._get_soar_user_wf.execute(user_id=user_id)

    def list_soc_roles(self, limit: int = 100) -> SocRoleBatch:
        """Lists configured SOC roles and workflow assignment access hierarchy."""
        return self._list_soc_roles_wf.execute(limit=limit)

    def get_company_settings(self) -> CompanySettingsBatch:
        """Retrieves tenant company rebranding and reporting settings."""
        return self._get_company_settings_wf.execute()

    def search_case_tag_definitions(
        self,
        query: str = "",
        match_criteria: str = "ALL",
        limit: int = 100,
    ) -> CaseTagDefinitionBatch:
        """Discovers and filters case tag classification rules."""
        return self._search_case_tags_wf.execute(
            query=query,
            match_criteria=match_criteria,
            limit=limit,
        )

    def list_case_stage_definitions(self, limit: int = 100) -> CaseStageDefinitionBatch:
        """Lists ordered SOC case lifecycle pipeline stage definitions."""
        return self._list_case_stages_wf.execute(limit=limit)

    def list_case_close_definitions(self, limit: int = 100) -> CaseCloseDefinitionBatch:
        """Catalogs predefined case close reasons and root causes."""
        return self._list_case_close_defs_wf.execute(limit=limit)

    def list_case_close_dynamic_parameters(
        self,
        limit: int = 100,
    ) -> CaseCloseDynamicParameterBatch:
        """Lists dynamic form parameters and custom field schemas for case closure."""
        return self._list_case_close_params_wf.execute(limit=limit)

    def get_case_title_settings(self) -> CaseTitleSettingsBatch:
        """Retrieves case title formatting priority rules."""
        return self._get_case_title_settings_wf.execute()

    def search_case_views(
        self,
        query: str = "",
        view_type: str = "",
        limit: int = 100,
    ) -> CaseViewBatch:
        """Discovers and filters layout view templates for Cases, Alerts, and Detections."""
        return self._search_case_views_wf.execute(
            query=query,
            view_type=view_type,
            limit=limit,
        )

    def get_case_view(self, view_id: str) -> CaseViewDetail:
        """Retrieves deep inspection of a specific view layout template and widget hierarchy."""
        return self._get_case_view_wf.execute(view_id=view_id)

    def search_custom_fields(
        self,
        query: str = "",
        field_type: str = "",
        scope: str = "",
        limit: int = 100,
    ) -> CustomFieldBatch:
        """Lists and filters custom typed fields across Case and Alert scopes."""
        return self._search_custom_fields_wf.execute(
            query=query,
            field_type=field_type,
            scope=scope,
            limit=limit,
        )

    def get_custom_field(self, field_id: str) -> CustomFieldDetail:
        """Retrieves deep inspection of a single custom field definition."""
        return self._get_custom_field_wf.execute(field_id=field_id)

    def search_calculated_fields(
        self,
        query: str = "",
        limit: int = 100,
    ) -> CalculatedFieldBatch:
        """Lists and filters calculated field formula definitions."""
        return self._search_calculated_fields_wf.execute(
            query=query,
            limit=limit,
        )

    def get_calculated_field(self, definition_id: str) -> CalculatedFieldDetail:
        """Retrieves deep inspection of a single calculated field definition."""
        return self._get_calculated_field_wf.execute(definition_id=definition_id)

    def search_alert_grouping_rules(
        self,
        query: str = "",
        category: str = "",
        limit: int = 100,
    ) -> AlertGroupingRuleBatch:
        """Discovers and filters SOAR alert grouping rules determining case clustering."""
        return self._search_alert_grouping_rules_wf.execute(
            query=query,
            category=category,
            limit=limit,
        )

    def get_alert_grouping_rule(self, rule_id: str) -> AlertGroupingRuleDetail:
        """Retrieves deep inspection of a single alert grouping rule."""
        return self._get_alert_grouping_rule_wf.execute(rule_id=rule_id)

    def get_alert_grouping_settings(self) -> AlertGroupingSettingsBatch:
        """Retrieves global SOAR alert grouping configuration parameters."""
        return self._get_alert_grouping_settings_wf.execute()

    def get_data_retention_settings(self) -> DataRetentionSettingsBatch:
        """Retrieves SOAR data retention configuration and environment policy settings."""
        return self._get_data_retention_settings_wf.execute()

    def search_environments(
        self,
        query: str = "",
        limit: int = 100,
    ) -> EnvironmentBatch:
        """Discovers and filters multi-tenancy environments."""
        return self._search_environments_wf.execute(
            query=query if query else None,
            limit=limit,
        )

    def get_environment(self, env_id: str) -> EnvironmentDetail:
        """Retrieves deep configuration of a single multi-tenancy environment."""
        return self._get_environment_wf.execute(env_id=env_id)

    def search_environment_groups(
        self,
        query: str = "",
        limit: int = 100,
    ) -> EnvironmentGroupBatch:
        """Discovers and lists logical groupings of multi-tenancy environments."""
        return self._search_environment_groups_wf.execute(
            query=query if query else None,
            limit=limit,
        )

    def search_remote_agents(
        self,
        query: str = "",
        environment: str = "",
        agent_state: str = "",
        limit: int = 100,
    ) -> RemoteAgentBatch:
        """Discovers and filters remote SOAR agents."""
        return self._search_remote_agents_wf.execute(
            query=query if query else None,
            environment=environment if environment else None,
            agent_state=agent_state if agent_state else None,
            limit=limit,
        )

    def get_remote_agent(self, agent_id: str) -> RemoteAgentDetail:
        """Retrieves deep configuration of a single remote agent."""
        return self._get_remote_agent_wf.execute(agent_id=agent_id)

    def get_email_settings(self) -> EmailSettingsBatch:
        """Retrieves composite email transport configuration."""
        return self._get_email_settings_wf.execute()

    def get_support_settings(self) -> SupportSettingsBatch:
        """Retrieves Google Support access delegation properties."""
        return self._get_support_settings_wf.execute()

    def search_soar_networks(
        self,
        query: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> SoarNetworkBatch:
        """Discovers and filters customer-defined CIDR network address ranges."""
        return self._search_soar_networks_wf.execute(
            query=query if query else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_soar_network(self, network_id: str) -> SoarNetworkDetail:
        """Retrieves deep configuration of a single customer-defined CIDR network."""
        return self._get_soar_network_wf.execute(network_id=network_id)

    def search_soar_domains(
        self,
        query: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> SoarDomainBatch:
        """Discovers and filters approved customer domain names."""
        return self._search_soar_domains_wf.execute(
            query=query if query else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_soar_domain(self, domain_id: str) -> SoarDomainDetail:
        """Retrieves deep configuration of a single approved customer domain."""
        return self._get_soar_domain_wf.execute(domain_id=domain_id)

    def search_soar_custom_lists(
        self,
        query: str = "",
        category: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> SoarCustomListBatch:
        """Discovers and filters SOAR custom list key-value retention entries."""
        return self._search_soar_custom_lists_wf.execute(
            query=query if query else None,
            category=category if category else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_soar_custom_list(self, list_id: str) -> SoarCustomListDetail:
        """Retrieves deep configuration of a single SOAR custom list entry."""
        return self._get_soar_custom_list_wf.execute(list_id=list_id)

    def search_email_templates(
        self,
        query: str = "",
        template_type: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> EmailTemplateBatch:
        """Discovers and filters email templates (plain text and HTML)."""
        return self._search_email_templates_wf.execute(
            query=query if query else None,
            template_type=template_type if template_type else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_email_template(self, template_id: str) -> EmailTemplateDetail:
        """Retrieves deep configuration and content of a single email template."""
        return self._get_email_template_wf.execute(template_id=template_id)

    def search_entities_blocklists(
        self,
        query: str = "",
        entity_type: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> EntitiesBlocklistBatch:
        """Discovers and filters entity noise-reduction blocklist rules."""
        return self._search_entities_blocklists_wf.execute(
            query=query if query else None,
            entity_type=entity_type if entity_type else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_entities_blocklist(self, blocklist_id: str) -> EntitiesBlocklistDetail:
        """Retrieves deep configuration of a single entity blocklist entry."""
        return self._get_entities_blocklist_wf.execute(blocklist_id=blocklist_id)

    def search_sla_definitions(
        self,
        query: str = "",
        sla_type: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> SlaDefinitionBatch:
        """Discovers and filters Service Level Agreement definitions."""
        return self._search_sla_definitions_wf.execute(
            query=query if query else None,
            sla_type=sla_type if sla_type else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_sla_definition(self, sla_id: str) -> SlaDefinitionDetail:
        """Retrieves deep configuration of a single SLA definition."""
        return self._get_sla_definition_wf.execute(sla_id=sla_id)

    def search_request_templates(
        self,
        query: str = "",
        environment: str = "",
        limit: int = 100,
    ) -> RequestTemplateBatch:
        """Discovers and filters manual case request form templates."""
        return self._search_request_templates_wf.execute(
            query=query if query else None,
            environment=environment if environment else None,
            limit=limit,
        )

    def get_request_template(self, template_id: str) -> RequestTemplateDetail:
        """Retrieves deep configuration and field definitions of a single request template."""
        return self._get_request_template_wf.execute(template_id=template_id)

    def search_soar_ingestion_connectors(
        self,
        query: str = "",
        integration: str = "-",
        connector_id: str = "-",
        environment: str = "",
        enabled_only: bool = False,
        limit: int = 100,
    ) -> SoarIngestionConnectorBatch:
        """Discovers and filters configured SOAR ingestion connector instances across integrations."""
        return self._search_soar_ingestion_connectors_wf.execute(
            query=query if query else None,
            integration=integration,
            connector_id=connector_id,
            environment=environment if environment else None,
            enabled_only=enabled_only,
            limit=limit,
        )

    def get_soar_ingestion_connector(
        self,
        instance_id: str,
        integration: str = "-",
        connector_id: str = "-",
    ) -> SoarIngestionConnectorDetail:
        """Retrieves deep configuration of a single SOAR ingestion connector instance."""
        return self._get_soar_ingestion_connector_wf.execute(
            instance_id=instance_id,
            integration=integration,
            connector_id=connector_id,
        )

    def search_soar_webhooks(
        self,
        query: str = "",
        environment: str = "",
        enabled_only: bool = False,
        limit: int = 100,
    ) -> SoarWebhookBatch:
        """Discovers and filters configured SOAR event ingestion webhooks."""
        return self._search_soar_webhooks_wf.execute(
            query=query if query else None,
            environment=environment if environment else None,
            enabled_only=enabled_only,
            limit=limit,
        )

    def get_soar_webhook(self, webhook_id: str) -> SoarWebhookDetail:
        """Retrieves deep configuration and JSON schema mapping of a single SOAR event ingestion webhook."""
        return self._get_soar_webhook_wf.execute(webhook_id=webhook_id)

    def detect_entity(self, value: str, hint: Optional[str] = None) -> DetectedEntity:
        """Detects entity indicator type, category, and canonical graph & event queries.

        Pass ``hint`` (our EntityType names or SOAR involved-entity type strings) to
        override the regex heuristics when the caller already knows the type.
        """
        return detect_entity(value, hint=hint)

    def search_entity_graph(
        self,
        indicator_or_field: str,
        value: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        receive_limit: int = 10000,
        batch_size: int = 2000,
        hint: Optional[str] = None,
        on_batch: Optional[Callable[[SearchBatchResult, SearchSession], None]] = None,
        on_state_change: Optional[Callable[[SearchSession], None]] = None,
        cancel_token: Optional[Callable[[], bool]] = None,
    ) -> SearchSession:
        """Executes streaming search against the UDM entity graph (graph.entity.*).

        Pass ``hint`` (SOAR entity_type or our EntityType) to bypass the ambiguous
        regex classification when the type is already known.
        """
        return self._search_entity_graph_wf.execute(
            indicator_or_field=indicator_or_field,
            value=value,
            start_time=start_time,
            end_time=end_time,
            receive_limit=receive_limit,
            batch_size=batch_size,
            hint=hint,
            on_batch=on_batch,
            on_state_change=on_state_change,
            cancel_token=cancel_token,
        )

    def search_enterprise_iocs(
        self,
        value: str,
        value_type: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_matches: int = 10000,
        add_mandiant_attributes: bool = True,
        lookback_days: Optional[int] = None,
    ) -> EnterpriseIocBatch:
        """Searches enterprise-wide IoC matches and Mandiant threat intel for an indicator.

        Without ``start_time`` the window is all time (epoch), or the last
        ``lookback_days`` when given. IPs auto-detect to ``ASSET_IP_ADDRESS``.
        """
        return self._search_enterprise_iocs_wf.execute(
            value=value,
            value_type=value_type,
            start_time=start_time,
            end_time=end_time,
            max_matches=max_matches,
            add_mandiant_attributes=add_mandiant_attributes,
            lookback_days=lookback_days,
        )

    def summarize_entity(
        self,
        entity_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        return_alerts: bool = False,
        return_prevalence: bool = True,
        include_all_udm_event_types: bool = True,
        field_value: Optional[str] = None,
        value_type: Optional[str] = None,
    ) -> EntitySummaryResult:
        """Retrieves entity summary profile, timeline intervals, and prevalence.

        Look up by ``entity_id`` or by ``field_value`` (+ ``value_type``, e.g.
        HOSTNAME / ASSET_IP_ADDRESS; auto-detected when omitted).
        """
        return self._summarize_entity_wf.execute(
            entity_id=entity_id,
            field_value=field_value,
            value_type=value_type,
            start_time=start_time,
            end_time=end_time,
            return_alerts=return_alerts,
            return_prevalence=return_prevalence,
            include_all_udm_event_types=include_all_udm_event_types,
        )

    def investigate_entity(
        self,
        indicator: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        max_events: int = 50,
        include_cases: bool = True,
    ) -> EntityInvestigationReport:
        """Executes full cross-engine correlation across Entity Graph, UDM Events, IoCs, and SOAR Cases."""
        return self._investigate_entity_wf.execute(
            indicator=indicator,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            include_cases=include_cases,
        )

    def list_capabilities(
        self,
        category: Optional[str] = None,
        domain: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> List[WorkflowCapability]:
        """Lists capabilities available in this engine instance."""
        return self.registry.list_capabilities(
            category=category,
            domain=domain,
            kind=kind,
        )

    # -------------------------------------------------------------------------
    # Chronicle SIEM Data Tables
    # -------------------------------------------------------------------------

    def list_data_tables(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        order_by: Optional[str] = None,
    ) -> DataTableListResult:
        """Lists structured data tables in Chronicle SIEM."""
        return self._list_data_tables_wf.execute(
            page_size=page_size,
            page_token=page_token,
            order_by=order_by,
        )

    def get_data_table(self, table_name_or_id: str) -> DataTable:
        """Gets schema and metadata for a specific Chronicle SIEM Data Table."""
        return self._get_data_table_wf.execute(table_name_or_id=table_name_or_id)

    def create_data_table(
        self,
        table_id: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        column_info: Optional[List[Dict[str, Any]]] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
    ) -> DataTable:
        """Creates a new structured Data Table with column definitions in Chronicle SIEM."""
        return self._create_data_table_wf.execute(
            table_id=table_id,
            display_name=display_name,
            description=description,
            column_info=column_info,
            row_time_to_live=row_time_to_live,
            scope_info=scope_info,
        )

    def patch_data_table(
        self,
        table_name_or_id: str,
        description: Optional[str] = None,
        row_time_to_live: Optional[str] = None,
        scope_info: Optional[Dict[str, Any]] = None,
        update_mask: Optional[str] = None,
    ) -> DataTable:
        """Updates description, TTL, or scope info of an existing Data Table."""
        return self._patch_data_table_wf.execute(
            table_name_or_id=table_name_or_id,
            description=description,
            row_time_to_live=row_time_to_live,
            scope_info=scope_info,
            update_mask=update_mask,
        )

    def delete_data_table(self, table_name_or_id: str) -> Dict[str, Any]:
        """Deletes a Chronicle SIEM Data Table."""
        return self._delete_data_table_wf.execute(table_name_or_id=table_name_or_id)

    def list_data_table_rows(
        self,
        table_name_or_id: str,
        page_size: int = 50,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
    ) -> DataTableRowListResult:
        """Lists rows contained within a Chronicle SIEM Data Table."""
        return self._list_data_table_rows_wf.execute(
            table_name_or_id=table_name_or_id,
            page_size=page_size,
            page_token=page_token,
            filter_expr=filter_expr,
        )

    def add_data_table_rows(
        self,
        table_name_or_id: str,
        rows: Union[List[Dict[str, Any]], Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Creates or appends rows in bulk to a Chronicle SIEM Data Table.

        Supports a single row dictionary or a list of row dictionaries.
        """
        row_list = [rows] if isinstance(rows, dict) else list(rows)
        return self._add_data_table_rows_wf.execute(
            table_name_or_id=table_name_or_id,
            rows=row_list,
        )

    def delete_data_table_row(
        self,
        table_name_or_id: str,
        row_id: str,
    ) -> Dict[str, Any]:
        """Deletes a single row from a Chronicle SIEM Data Table by row ID."""
        return self._delete_data_table_row_wf.execute(
            table_name_or_id=table_name_or_id,
            row_id=row_id,
        )

    def audit_data_table_health(
        self,
        lookback_days: int = 14,
        stale_days: int = 180,
        correlate_rules: bool = True,
        max_tables: int = 200,
    ) -> DataTableHealthReport:
        """Audits Data Tables for recency, schema hygiene, empty referenced detection risks, and lineage."""
        return self._audit_data_table_health_wf.execute(
            lookback_days=lookback_days,
            stale_days=stale_days,
            correlate_rules=correlate_rules,
            max_tables=max_tables,
        )

    # -------------------------------------------------------------------------
    # Custom YARA-L Detection Rules Facade Methods
    # -------------------------------------------------------------------------

    def list_rules(
        self,
        page_size: int = 100,
        page_token: Optional[str] = None,
        filter_expr: Optional[str] = None,
        view: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> RuleListResult:
        """Lists custom YARA-L detection rules in Chronicle SIEM.

        One page by default (backward compatible). ``all_pages=True`` follows
        ``nextPageToken`` to the end; ``max_results`` caps the item count.
        """
        return self._list_rules_wf.execute(
            page_size=page_size,
            page_token=page_token,
            filter_expr=filter_expr,
            view=view,
            all_pages=all_pages,
            max_results=max_results,
        )

    def get_rule(
        self,
        rule_id_or_name: str,
        view: str = "FULL",
    ) -> RuleDetail:
        """Retrieves full details and YARA-L logic of a detection rule."""
        return self._get_rule_wf.execute(
            rule_id_or_name=rule_id_or_name,
            view=view,
        )

    def verify_rule(self, rule_text: str) -> RuleValidationResult:
        """Validates YARA-L 2.0 rule syntax against the Chronicle compiler."""
        return self._verify_rule_wf.execute(rule_text=rule_text)

    def validate_rule(self, rule_text: str) -> RuleValidationResult:
        """Alias for verify_rule: validates YARA-L 2.0 rule syntax."""
        return self.verify_rule(rule_text=rule_text)

    def create_rule(self, rule_text: str) -> RuleDetail:
        """Creates a new YARA-L detection rule in Chronicle SIEM."""
        return self._create_rule_wf.execute(rule_text=rule_text)

    def patch_rule(
        self,
        rule_id_or_name: str,
        rule_text: str,
        update_mask: Optional[str] = None,
    ) -> RuleDetail:
        """Updates the YARA-L logic of an existing detection rule."""
        return self._patch_rule_wf.execute(
            rule_id_or_name=rule_id_or_name,
            rule_text=rule_text,
            update_mask=update_mask,
        )

    def delete_rule(self, rule_id_or_name: str) -> Dict[str, Any]:
        """Deletes a custom detection rule from Chronicle SIEM."""
        return self._delete_rule_wf.execute(rule_id_or_name=rule_id_or_name)

    def list_rule_revisions(
        self,
        rule_id_or_name: str,
        page_size: int = 100,
        page_token: Optional[str] = None,
    ) -> RuleRevisionListResult:
        """Lists historical revisions and version history of a detection rule."""
        return self._list_rule_revisions_wf.execute(
            rule_id_or_name=rule_id_or_name,
            page_size=page_size,
            page_token=page_token,
        )

    def list_rule_deployments(
        self,
        page_size: int = 1000,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
    ) -> RuleDeploymentListResult:
        """Lists deployment, frequency, and alerting status for all detection rules.

        ``all_pages=True`` follows ``nextPageToken`` to the end.
        """
        return self._list_rule_deployments_wf.execute(
            page_size=page_size,
            page_token=page_token,
            all_pages=all_pages,
            max_results=max_results,
        )

    def get_rule_deployment(self, rule_id_or_name: str) -> RuleDeployment:
        """Retrieves deployment, frequency, and alerting status of a rule."""
        return self._get_rule_deployment_wf.execute(rule_id_or_name=rule_id_or_name)

    def update_rule_deployment(
        self,
        rule_id_or_name: str,
        enabled: Optional[bool] = None,
        alerting: Optional[bool] = None,
        run_frequency: Optional[str] = None,
        update_mask: Optional[str] = None,
    ) -> RuleDeployment:
        """Updates deployment properties (enabled, alerting, frequency) of a rule."""
        return self._update_rule_deployment_wf.execute(
            rule_id_or_name=rule_id_or_name,
            enabled=parse_strict_bool(enabled, "enabled"),
            alerting=parse_strict_bool(alerting, "alerting"),
            run_frequency=run_frequency,
            update_mask=update_mask,
        )

    def list_rule_errors(
        self,
        rule_id_or_name: Optional[str] = None,
        page_size: int = 100,
        page_token: Optional[str] = None,
        all_pages: bool = False,
        max_results: Optional[int] = None,
        since: Optional[Any] = None,
    ) -> RuleExecutionErrorListResult:
        """Lists runtime and execution errors across detection rules.

        The API has no time filter. ``since`` (datetime or RFC3339) keeps
        errors whose ``timeRange.endTime`` is at or after it and implies
        ``all_pages=True``.
        """
        return self._list_rule_errors_wf.execute(
            rule_id_or_name=rule_id_or_name,
            page_size=page_size,
            page_token=page_token,
            all_pages=all_pages,
            max_results=max_results,
            since=since,
        )

    def audit_rule_health(
        self,
        include_curated: bool = True,
        latency_threshold_min: float = 30.0,
        page_size: int = 100,
        error_lookback_days: Optional[int] = None,
    ) -> RuleHealthReport:
        """Audits detection rule health, errors, latencies, and decay.

        Reads every page of rules, deployments and errors; curated rule sets
        are classified from their real deployments. Telemetry failures are
        reported in ``telemetry_errors`` / ``*_available``.
        ``error_lookback_days`` limits which execution errors count (None =
        full history, the previous behaviour).
        """
        return self._audit_rule_health_wf.execute(
            include_curated=include_curated,
            latency_threshold_min=latency_threshold_min,
            page_size=page_size,
            error_lookback_days=error_lookback_days,
        )

    def query_cloud_logging(
        self,
        filter_str: str,
        project_ids: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
        order_by: str = "timestamp desc",
    ) -> GcpLogQueryResult:
        """Queries Google Cloud Logging API for SecOps events, errors, and audit logs."""
        return self._query_cloud_logging_wf.execute(
            filter_str=filter_str,
            project_ids=project_ids,
            page_size=page_size,
            page_token=page_token,
            order_by=order_by,
        )

    def query_secops_errors(
        self,
        hours: int = 24,
        component: Optional[str] = None,
        page_size: int = 50,
    ) -> GcpLogQueryResult:
        """Queries Google Cloud Logging for SecOps operational errors."""
        return self._query_cloud_logging_wf.query_secops_errors(
            hours=hours, component=component, page_size=page_size
        )

    def query_secops_audit_logs(
        self,
        hours: int = 24,
        human_only: Optional[bool] = None,
        page_size: int = 50,
    ) -> GcpLogQueryResult:
        """Queries Google Cloud Logging for SecOps Cloud Audit activity logs."""
        return self._query_cloud_logging_wf.query_secops_audit_logs(
            hours=hours, human_only=human_only, page_size=page_size
        )

    def query_cloud_monitoring(
        self,
        filter_str: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        hours: int = 24,
        project_id: Optional[str] = None,
        alignment_period: Optional[str] = None,
        per_series_aligner: Optional[str] = None,
        cross_series_reducer: Optional[str] = None,
        group_by_fields: Optional[List[str]] = None,
        page_size: int = 50,
        page_token: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Google Cloud Monitoring time series for SecOps and Chronicle metrics."""
        return self._query_cloud_monitoring_wf.execute(
            filter_str=filter_str,
            start_time=start_time,
            end_time=end_time,
            hours=hours,
            project_id=project_id,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
            cross_series_reducer=cross_series_reducer,
            group_by_fields=group_by_fields,
            page_size=page_size,
            page_token=page_token,
        )

    def get_chronicle_ingestion_metrics(
        self,
        metric: str = "ingestion/log/record_count",
        lookback_hours: int = 24,
        log_types: Optional[List[str]] = None,
        group_by_log_type: bool = True,
        alignment_period_s: int = 3600,
        project_id: Optional[str] = None,
        hours: Optional[int] = None,
        log_type: Optional[str] = None,
    ) -> ChronicleIngestionMetricsResult:
        """Queries one Chronicle ingestion metric from Cloud Monitoring, per log type.

        Args:
            metric: One of ``ingestion/log/record_count`` (default),
                ``ingestion/log/bytes_count``, ``normalizer/log/record_count``.
            lookback_hours: Window ending now.
            log_types: Optional filter on ``resource.label.log_type``.
            group_by_log_type: REDUCE_SUM grouped by log type (True) or one
                ``"ALL"`` series (False).
            alignment_period_s: ALIGN_SUM alignment period in seconds (default 3600).
            project_id: Cloud project hosting the Chronicle metrics (default: adapter project).
            hours: Backward-compatible alias for ``lookback_hours``.
            log_type: Backward-compatible alias for ``log_types=[log_type]``.
        """
        if hours is not None:
            lookback_hours = hours
        if log_type:
            log_types = list(log_types or []) + [log_type]
        return self._query_cloud_monitoring_wf.query_chronicle_ingestion_series(
            metric=metric,
            lookback_hours=lookback_hours,
            log_types=log_types,
            group_by_log_type=group_by_log_type,
            alignment_period_s=alignment_period_s,
            project_id=project_id,
        )

    def get_chronicle_normalizer_metrics(
        self,
        hours: int = 24,
        log_type: Optional[str] = None,
        alignment_period: str = "3600s",
        per_series_aligner: str = "ALIGN_SUM",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle normalizer and parser throughput metrics."""
        return self._query_cloud_monitoring_wf.query_chronicle_normalizer_metrics(
            hours=hours,
            log_type=log_type,
            alignment_period=alignment_period,
            per_series_aligner=per_series_aligner,
            project_id=project_id,
        )

    def get_chronicle_api_metrics(
        self,
        hours: int = 24,
        alignment_period: str = "3600s",
        project_id: Optional[str] = None,
    ) -> GcpMonitoringQueryResult:
        """Queries Chronicle API consumption and request count metrics."""
        return self._query_cloud_monitoring_wf.query_chronicle_api_metrics(
            hours=hours,
            alignment_period=alignment_period,
            project_id=project_id,
        )

    @property
    def _identity_governance_wf(self) -> IdentityGovernanceWorkflow:
        if not hasattr(self, "_identity_governance_workflow_instance") or self._identity_governance_workflow_instance is None:
            self._identity_governance_workflow_instance = IdentityGovernanceWorkflow(self.adapter)
        return self._identity_governance_workflow_instance

    def get_chronicle_iam_bindings(
        self,
        project_id: Optional[str] = None,
    ) -> List[ChronicleIamRoleBinding]:
        """Audits project GCP IAM policy for default and custom Chronicle roles."""
        return self._identity_governance_wf.get_chronicle_iam_bindings(project_id=project_id)

    def get_chronicle_custom_roles(
        self,
        project_id: Optional[str] = None,
    ) -> List[ChronicleCustomRole]:
        """Lists custom GCP IAM roles within the project granting chronicle.* permissions."""
        return self._identity_governance_wf.get_chronicle_custom_roles(project_id=project_id)

    def fetch_inventory_identity_report(
        self,
        inventory_base_url: str = "http://localhost:8000",
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieves identity access insights from the SecOps Inventory service."""
        return self._identity_governance_wf.fetch_inventory_identity_report(
            inventory_base_url=inventory_base_url,
            tenant_id=tenant_id,
        )

    def generate_identity_governance_report(
        self,
        project_id: Optional[str] = None,
        inventory_base_url: str = "http://localhost:8000",
    ) -> IdentityGovernanceReport:
        """Generates a complete Identity Governance report combining IAM bindings, custom roles, and inventory data."""
        return self._identity_governance_wf.generate_governance_report(
            project_id=project_id,
            inventory_base_url=inventory_base_url,
        )

    def audit_rule_decay(
        self,
        rule_id: Optional[str] = None,
        lookback_days: int = 90,
        check_population: bool = True,
        schema_cache: Optional[Any] = None,
        max_workers: int = 4,
    ) -> RuleDecayReport:
        """Audits detection rules for compilation breakage, silence, staleness, and unpopulated UDM fields with DPS scoring.

        Read-only when ``schema_cache`` is None. Telemetry and per-rule check
        failures are reported (``telemetry_available``, ``telemetry_errors``,
        ``check_errors``), never turned into SILENT / BROKEN_COMPILATION.
        """
        return self._audit_rule_decay_wf.execute(
            rule_id=rule_id,
            lookback_days=lookback_days,
            check_population=check_population,
            schema_cache=schema_cache,
            max_workers=max_workers,
        )

    def get_rule_detection_counts(
        self,
        lookback_days: int = 90,
    ) -> Dict[str, Dict[str, Any]]:
        """Queries 90-day detection count aggregations using authoritative native detection schema.

        Raises on query failure (an empty dict means no rule fired).
        """
        return self._query_rule_detection_counts_wf.execute(lookback_days=lookback_days)

    def get_rule_detection_series(
        self,
        lookback_hours: int = 24,
        bucket: str = "hour",
        rule_ids: Optional[Union[List[str], str]] = None,
    ) -> RuleDetectionSeriesResult:
        """Per-rule detection counts bucketed by ``"hour"`` or ``"day"`` (UTC), oldest first.

        One dashboard query; raises on query error. Each series has
        ``rule_id``, ``rule_name`` and ``buckets`` of ``(bucket_start, count)``;
        empty buckets are omitted.
        """
        ids = parse_id_list(rule_ids, "rule_ids") if rule_ids else None
        return self._query_rule_detection_series_wf.execute(
            lookback_hours=lookback_hours,
            bucket=bucket,
            rule_ids=ids or None,
        )

    def audit_udm_field_population(
        self,
        field_paths: List[str],
        vendor_product: Optional[str] = None,
        lookback_days: int = 30,
        schema_cache: Optional[Any] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Audits live UDM field population for detection rule telemetry."""
        return self._audit_udm_population_wf.execute(
            field_paths=field_paths,
            vendor_product=vendor_product,
            lookback_days=lookback_days,
            schema_cache=schema_cache,
        )

    def audit_rule_conflicts(
        self,
        rule_id: str,
        limit: int = 6,
    ) -> RuleConflictAuditResult:
        """Audits detection rule for semantic overlaps, contradictions, redundancies, and computes COS."""
        return self._audit_rule_conflict_wf.execute(rule_id=rule_id, limit=limit)

    def batch_audit_rule_conflicts(
        self,
        limit: int = 50,
        batch_size: int = 10,
        min_cos: float = 45.0,
    ) -> BatchRuleConflictAuditResult:
        """Discovers and scores rule conflicts and overlaps across all tenant active rules."""
        return self._batch_audit_rule_conflicts_wf.execute(limit=limit, batch_size=batch_size, min_cos=min_cos)

    def find_similar_rules(
        self,
        rule_id: str,
        limit: int = 6,
        auto_embed: bool = True,
        persist: bool = True,
    ) -> List[Dict[str, Any]]:
        """Finds candidate overlapping or conflicting rules via vector similarity search.

        On a cache miss the target rule is embedded (``auto_embed``) and, if
        ``persist``, the embedding is saved. ``persist=False`` searches with
        the fresh embedding without writing; ``auto_embed=False`` only reads
        the existing vector store.
        """
        return self._find_similar_rules_wf.execute(
            rule_id=rule_id, limit=limit, auto_embed=auto_embed, persist=persist
        )

    def sync_rule_embeddings(
        self,
        batch_size: int = 50,
        force_refresh: bool = False,
        include_curated: bool = True,
    ) -> Dict[str, Any]:
        """Synchronizes vector embeddings for all active tenant detection rules in batches."""
        return self._sync_rule_embeddings_wf.execute(
            batch_size=batch_size,
            force_refresh=force_refresh,
            include_curated=include_curated,
        )

    def audit_rules(
        self,
        include_curated: bool = True,
        sync_embeddings: bool = True,
        lookback_days: int = 90,
        run_conflict_scan: bool = True,
        batch_size: int = 50,
        page_size: int = 1000,
    ) -> RuleAuditReport:
        """Executes full detection rule repository audit across custom and curated rules."""
        return self._audit_rules_wf.execute(
            include_curated=include_curated,
            sync_embeddings=sync_embeddings,
            lookback_days=lookback_days,
            run_conflict_scan=run_conflict_scan,
            batch_size=batch_size,
            page_size=page_size,
        )

    def analyze_log_costs(
        self,
        lookback_days: int = 7,
        pricing_tier: str = "ENTERPRISE",
        bloat_threshold_bytes: int = 2048,
    ) -> LogCostAnalysisReport:
        """Executes ingestion telemetry analysis, multi-tier pricing, and FinOps evaluation."""
        return self._analyze_log_cost_wf.execute(
            lookback_days=lookback_days,
            pricing_tier=pricing_tier,
            bloat_threshold_bytes=bloat_threshold_bytes,
        )

    def get_latest_log_costs(self, fallback_if_empty: bool = True) -> Optional[Dict[str, Any]]:
        """Retrieves the latest cached or persisted Log Cost Analysis Report from Evidence Fabric."""
        return self._get_latest_log_cost_wf.execute(fallback_if_empty=fallback_if_empty)

    def analyze_ingestion_labels(self, lookback_days: int = 7) -> List[IngestionLabelMetric]:
        """Analyzes active ingestion labels and tagging consistency across log types."""
        return self._analyze_ingestion_labels_wf.execute(lookback_days=lookback_days)

    def analyze_namespaces(self, lookback_days: int = 7) -> List[NamespaceMetric]:
        """Analyzes active UDM namespaces and detects RFC 1918 private IP collision risks."""
        return self._analyze_namespaces_wf.execute(lookback_days=lookback_days)

    def audit_data_rbac_alignment(
        self,
        active_label_keys: Optional[Set[str]] = None,
        active_namespaces: Optional[Set[str]] = None,
    ) -> List[DataRbacLabelReference]:
        """Audits Data Access Labels for backing in active telemetry tags and namespaces."""
        return self._audit_data_rbac_alignment_wf.execute(
            active_label_keys=active_label_keys,
            active_namespaces=active_namespaces,
        )

    def analyze_labels_and_namespaces(self, lookback_days: int = 7) -> NamespaceLabelAnalysisReport:
        """Executes full hygiene audit across ingestion labels, namespaces, and Data RBAC."""
        return self._analyze_namespace_labels_wf.execute(lookback_days=lookback_days)

    def get_identity_fidelity(self, days: int = 7, limit: int = 50) -> List[IdentityFidelityMetric]:
        """Profiles the population density of distinct user identity keys across all active log types."""
        return self._tenant_profiling_wf.get_identity_fidelity(days=days, limit=limit)

    def get_entity_graph_lineage(self, days: int = 7, limit: int = 50) -> List[EntityGraphSource]:
        """Profiles the provenance, vendors, products, and longevity of entity graph bindings."""
        return self._tenant_profiling_wf.get_entity_graph_lineage(days=days, limit=limit)

    def get_log_source_volume_pareto(self, days: int = 7, limit: int = 50) -> List[LogSourceVolumeMetric]:
        """Profiles total event volume and ingestion temporal bounds per log source."""
        return self._tenant_profiling_wf.get_log_source_volume_pareto(days=days, limit=limit)

    def generate_tenant_telemetry_profile(self, days: int = 7, limit: int = 50) -> TenantTelemetryProfile:
        """Executes full tenant survey and synthesizes an Attested TenantTelemetryProfile."""
        return self._tenant_profiling_wf.generate_tenant_telemetry_profile(days=days, limit=limit)

    def export_attested_computation_markdown(
        self, profile: TenantTelemetryProfile, output_path: Optional[str] = None
    ) -> str:
        """Formats the profile as an Open Knowledge Format (OKF v0.2) Attested Computation document."""
        return self._tenant_profiling_wf.export_attested_computation_markdown(profile, output_path=output_path)

    def generate_shift_briefing(
        self, shift_hours: int = 8, shift_name: Optional[str] = None
    ) -> ShiftBriefing:
        """Deterministically aggregates operational deltas and issues into a structured ShiftBriefing."""
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=shift_hours)
        return compute_shift_delta(
            start_time=start,
            end_time=now,
            shift_name=shift_name,
        )

    def generate_posture_snapshot(self) -> KnowledgeSnapshot:
        """Deterministically compiles the current SOC Knowledge & Posture Snapshot."""
        return compute_knowledge_snapshot()

    def get_composite_entity_dossier(
        self, subject_type: str, subject_id: str
    ) -> Dict[str, Any]:
        """Synthesizes cross-agent observations, status, and knowledge gaps for an entity."""
        from agents.core.knowledge_store import get_knowledge_store  # deferred: avoids engine<->agents.core cycle

        store = get_knowledge_store()
        return store.get_composite_entity(subject_type, subject_id)

    def sync_mitre_rules(
        self,
        force_refresh: bool = False,
        include_curated: bool = True,
        max_rules: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Synchronizes customer and curated detection rules into Firestore with parsed MITRE technique IDs."""
        return self._sync_mitre_rules_wf.execute(
            force_refresh=force_refresh,
            include_curated=include_curated,
            max_rules=max_rules,
        )

    def analyze_mitre_coverage(
        self,
        profile_id: str = "global_baseline",
        sync_cache_if_empty: bool = True,
        time_unit: str = "DAY",
        time_value: str = "7",
        persist: bool = True,
    ) -> MitreCoverageAssessment:
        """Evaluates detection rules and ingestion telemetry against MITRE ATT&CK matrix and threat profile.

        ``persist=False`` writes nothing: no cache sync (even when the cache is
        empty and ``sync_cache_if_empty``) and no saved assessment.
        """
        return self._analyze_mitre_coverage_wf.execute(
            profile_id=profile_id,
            sync_cache_if_empty=sync_cache_if_empty,
            time_unit=time_unit,
            time_value=time_value,
            persist=persist,
        )

    def get_technique_rules(self, technique_id: str) -> List[Dict[str, Any]]:
        """Retrieves all detection rules mapped to a specific MITRE ATT&CK technique."""
        catalog = MitreCatalog.get_instance()
        clean_tid = catalog.normalize_technique_id(technique_id)
        store = self.evidence_store
        if store is None:
            from agents.core.evidence_store import get_evidence_store
            store = get_evidence_store()
        rules = store.list_rule_states(limit=10000)
        matching = []
        for r in rules:
            techs = [catalog.normalize_technique_id(t) for t in r.get("mitre_techniques", [])]
            if clean_tid in techs:
                matching.append(r)
        return matching

    def list_mitre_threat_profiles(self) -> List[Dict[str, Any]]:
        """Lists available MITRE threat profiles."""
        catalog = MitreCatalog.get_instance()
        return catalog.list_threat_profiles()

    def generate_mitre_report(
        self,
        assessment: Optional[MitreCoverageAssessment] = None,
        profile_id: str = "global_baseline",
    ) -> Dict[str, Any]:
        """Generates an executive Markdown report and tactical gap analysis for MITRE ATT&CK posture."""
        return self._generate_mitre_report_wf.execute(
            assessment=assessment,
            profile_id=profile_id,
        )

    def query_cloud_status_incidents(
        self,
        service_name: Optional[str] = "Google SecOps",
        only_active: bool = False,
        region: Optional[str] = None,
        lookback_days: int = 30,
    ) -> List[CloudStatusIncident]:
        """Queries Google Cloud Security Status feed for service incidents."""
        from engine.workflows.cloud_status import fetch_security_incidents
        return fetch_security_incidents(
            service_name=service_name,
            only_active=only_active,
            region=region,
            lookback_days=lookback_days,
        )

    def audit_cloud_service_status(
        self,
        service_name: str = "Google SecOps",
        region: Optional[str] = None,
        lookback_days: int = 14,
    ) -> CloudStatusReport:
        """Audits overall Google SecOps platform health and external incidents."""
        from engine.workflows.cloud_status import audit_cloud_service_status
        return audit_cloud_service_status(
            service_name=service_name,
            region=region,
            lookback_days=lookback_days,
        )

    def correlate_cloud_incident(
        self,
        incident_id: str,
    ) -> Dict[str, Any]:
        """Correlates an external Google Cloud status incident with tenant telemetry and forwarder latency."""
        from engine.workflows.cloud_status import correlate_incident_with_telemetry
        return correlate_incident_with_telemetry(
            incident_id=incident_id,
            engine=self,
        )

    def sync_secops_homepage_dashboard(
        self,
        dashboard_name: str = "Google SecOps Homepage",
        dashboard_id: Optional[str] = None,
        status_lookback_days: int = 30,
        max_release_notes: int = 4,
        max_community_posts: int = 6,
        community_categories: Optional[Any] = None,
        include_tenant_health: bool = True,
        ai_executive_summary: Optional[str] = None,
        dashboard_title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates or updates the Google SecOps Homepage Native Dashboard with Markdown, KPI Visualization, and Button widgets from live status, release notes, community feeds, and tenant telemetry."""
        from engine.workflows.homepage_dashboard import SyncSecOpsHomepageDashboardWorkflow
        resolved_title = (dashboard_title or dashboard_name or "Google SecOps Homepage").strip()
        wf = SyncSecOpsHomepageDashboardWorkflow(adapter=self.adapter)
        return wf.execute(
            dashboard_title=resolved_title,
            dashboard_id=dashboard_id,
            status_lookback_days=status_lookback_days,
            max_release_notes=max_release_notes,
            max_community_posts=max_community_posts,
            community_categories=community_categories,
            include_tenant_health=include_tenant_health,
            ai_executive_summary=ai_executive_summary,
        )

