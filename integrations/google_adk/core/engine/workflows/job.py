"""SOAR Job, Instance, and Execution Log Workflows (Milestone 5.5).

Implements discovery, search, instance binding, schedule inspection, and execution log
retrieval for Google SecOps SOAR Scheduled Jobs.
Invariants: Strict live API provenance, zero synthetic data, explicit error visibility.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine.domain import (
    JobBatch,
    JobDetail,
    JobExecutionLog,
    JobExecutionStatus,
    JobInstance,
    JobSearchQuery,
    JobSummary,
)


def _parse_job_id_from_name(name: str) -> str:
    """Extracts job numeric ID from resource path '.../integrations/{int}/jobs/{id}'."""
    if "/jobs/" in name:
        return name.split("/jobs/")[1].split("/")[0]
    return ""


def _parse_job_instance_id_from_name(name: str) -> str:
    """Extracts job instance numeric ID from resource path '.../jobInstances/{id}'."""
    if "/jobInstances/" in name:
        return name.split("/jobInstances/")[1].split("/")[0]
    return ""


def _parse_integration_from_name(name: str) -> str:
    """Extracts integration identifier from resource path."""
    if "/integrations/" in name:
        parts = name.split("/integrations/")[1].split("/")
        if parts:
            return parts[0]
    return ""


class SearchJobsWorkflow:
    """Searches, lists, and filters SOAR scheduled jobs with aggregated instance counts."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(self, query: Optional[JobSearchQuery] = None) -> JobBatch:
        q = query or JobSearchQuery()

        # 1. Fetch live jobs
        raw_jobs = self.adapter.list_jobs(
            integration=q.integration,
            enabled=q.enabled,
            exclude_staging=True,
            page_size=1000,
        )

        # 2. Fetch live job instances to calculate instance counts
        raw_instances = self.adapter.list_job_instances(
            integration=q.integration,
            page_size=1000,
        )

        instance_count_by_job: Dict[str, int] = {}
        for inst in raw_instances:
            inst_job_name = inst.get("job", "")
            inst_job_id = _parse_job_id_from_name(inst.get("name", ""))
            if inst_job_id:
                instance_count_by_job[inst_job_id] = instance_count_by_job.get(inst_job_id, 0) + 1
            if inst_job_name:
                instance_count_by_job[inst_job_name] = instance_count_by_job.get(inst_job_name, 0) + 1

        summaries: List[JobSummary] = []
        term = q.query.lower().strip() if q.query else None

        for j in raw_jobs:
            name = j.get("name", "")
            job_id = str(j.get("id")) if j.get("id") else _parse_job_id_from_name(name)
            display_name = j.get("displayName") or name.split("/")[-1]
            description = j.get("description", "") or ""
            integration = j.get("integration") or _parse_integration_from_name(name)
            enabled = bool(j.get("enabled", False))

            # Filter by keyword if provided
            if term:
                searchable = f"{display_name} {description} {integration} {job_id}".lower()
                if term not in searchable:
                    continue

            # Filter by integration if provided
            if q.integration and integration.lower() != q.integration.lower():
                continue

            # Filter by enabled state if provided
            if q.enabled is not None and enabled != q.enabled:
                continue

            inst_count = instance_count_by_job.get(job_id, instance_count_by_job.get(display_name, 0))

            summary = JobSummary(
                id=job_id,
                name=name,
                display_name=display_name,
                description=description,
                integration=integration,
                enabled=enabled,
                cron_expression=j.get("cronExpression"),
                recurring_type=j.get("recurringType"),
                interval=j.get("interval"),
                timeout=j.get("timeout"),
                instances_count=inst_count,
                author=j.get("author"),
                creation_time=j.get("creationTime"),
                modification_time=j.get("modificationTime"),
                raw=j,
            )
            summaries.append(summary)

        # Sort: jobs with active instances first, then by display name
        summaries.sort(key=lambda x: (-x.instances_count, x.display_name.lower()))
        limited = summaries[: q.limit] if q.limit else summaries

        return JobBatch(
            results=limited,
            total_count=len(summaries),
            retrieved_at=datetime.now(timezone.utc),
        )


class GetJobDetailWorkflow:
    """Retrieves full details for a SOAR job including deployed instances and recent logs."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(self, integration: str, job_id: str) -> JobDetail:
        # 1. Fetch live job definition
        raw_job = self.adapter.get_job(integration=integration, job_id=job_id)
        if not raw_job:
            raise ValueError(f"Job not found for integration '{integration}' and job ID '{job_id}'")

        name = raw_job.get("name", "")
        extracted_id = str(raw_job.get("id")) if raw_job.get("id") else (_parse_job_id_from_name(name) or job_id)
        display_name = raw_job.get("displayName") or name.split("/")[-1]

        # 2. Fetch instances for this job
        raw_instances = self.adapter.list_job_instances(integration=integration, job_id=job_id)
        # If per-job query returned empty, try fallback by querying all instances for integration
        if not raw_instances:
            all_int_instances = self.adapter.list_job_instances(integration=integration)
            raw_instances = [
                inst for inst in all_int_instances
                if _parse_job_id_from_name(inst.get("name", "")) == str(job_id) or inst.get("job") == display_name
            ]

        instances: List[JobInstance] = []
        recent_logs: List[JobExecutionLog] = []

        for inst in raw_instances:
            inst_name = inst.get("name", "")
            inst_id = str(inst.get("id")) if inst.get("id") else _parse_job_instance_id_from_name(inst_name)
            inst_display = inst.get("displayName") or inst_name.split("/")[-1]
            inst_status = inst.get("status") or "UNKNOWN"
            inst_last_status = inst.get("lastRunStatus") or inst_status

            job_instance = JobInstance(
                id=inst_id,
                name=inst_name,
                display_name=inst_display,
                job_id=extracted_id,
                job_name=inst.get("job") or display_name,
                integration=inst.get("integration") or integration,
                environment=inst.get("environment"),
                status=inst_status,
                last_run_status=inst_last_status,
                last_run_time=inst.get("lastRunTime"),
                remote_agent_id=inst.get("remoteAgentId") or inst.get("agent"),
                schedule_type=inst.get("advancedConfig", {}).get("scheduleType"),
                advanced_config=inst.get("advancedConfig", {}),
                unique_identifier=inst.get("uniqueIdentifier"),
                raw=inst,
            )
            instances.append(job_instance)

            # 3. If there is a primary instance, fetch its latest logs
            if inst_id:
                try:
                    logs_data = self.adapter.get_job_instance_logs(instance_id=inst_id, page_size=5)
                    raw_logs = logs_data.get("logs", [])
                    for lg in raw_logs:
                        recent_logs.append(
                            JobExecutionLog(
                                name=lg.get("name", ""),
                                start_time=lg.get("startTime"),
                                end_time=lg.get("endTime"),
                                status=lg.get("status", "UNKNOWN"),
                                log_text=lg.get("message") or lg.get("log", "") or "",
                                job_identifier=lg.get("jobIdentifier", extracted_id),
                                integration=lg.get("integration", integration),
                                job_instance_id=lg.get("jobInstanceId", inst_id),
                                raw=lg,
                            )
                        )
                except Exception:
                    pass

        job_summary = JobSummary(
            id=extracted_id,
            name=name,
            display_name=display_name,
            description=raw_job.get("description", "") or "",
            integration=raw_job.get("integration") or integration,
            enabled=bool(raw_job.get("enabled", False)),
            cron_expression=raw_job.get("cronExpression"),
            recurring_type=raw_job.get("recurringType"),
            interval=raw_job.get("interval"),
            timeout=raw_job.get("timeout"),
            instances_count=len(instances),
            author=raw_job.get("author"),
            creation_time=raw_job.get("creationTime"),
            modification_time=raw_job.get("modificationTime"),
            raw=raw_job,
        )

        return JobDetail(
            job=job_summary,
            instances=instances,
            recent_logs=recent_logs,
        )


class ListJobInstancesWorkflow:
    """Lists runtime job instances across all jobs or filtered by integration / job ID."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        integration: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> List[JobInstance]:
        raw_instances = self.adapter.list_job_instances(
            integration=integration,
            job_id=job_id,
            page_size=1000,
        )

        instances: List[JobInstance] = []
        for inst in raw_instances:
            inst_name = inst.get("name", "")
            inst_id = str(inst.get("id")) if inst.get("id") else _parse_job_instance_id_from_name(inst_name)
            extracted_job_id = _parse_job_id_from_name(inst_name)
            extracted_int = _parse_integration_from_name(inst_name) or (integration or "")

            instances.append(
                JobInstance(
                    id=inst_id,
                    name=inst_name,
                    display_name=inst.get("displayName") or inst_name.split("/")[-1],
                    job_id=extracted_job_id or (job_id or ""),
                    job_name=inst.get("job", ""),
                    integration=inst.get("integration") or extracted_int,
                    environment=inst.get("environment"),
                    status=inst.get("status") or "UNKNOWN",
                    last_run_status=inst.get("lastRunStatus") or "UNKNOWN",
                    last_run_time=inst.get("lastRunTime"),
                    remote_agent_id=inst.get("remoteAgentId") or inst.get("agent"),
                    schedule_type=inst.get("advancedConfig", {}).get("scheduleType"),
                    advanced_config=inst.get("advancedConfig", {}),
                    unique_identifier=inst.get("uniqueIdentifier"),
                    raw=inst,
                )
            )

        return instances


class GetJobInstanceLogsWorkflow:
    """Retrieves execution run records and text logs for a specific job instance."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        job_instance_id: str,
        limit: int = 20,
        order_by: str = "endTime desc",
    ) -> List[JobExecutionLog]:
        logs_data = self.adapter.get_job_instance_logs(
            instance_id=job_instance_id,
            page_size=limit,
            order_by=order_by,
        )
        raw_logs = logs_data.get("logs", [])

        results: List[JobExecutionLog] = []
        for lg in raw_logs:
            results.append(
                JobExecutionLog(
                    name=lg.get("name", ""),
                    start_time=lg.get("startTime"),
                    end_time=lg.get("endTime"),
                    status=lg.get("status", "UNKNOWN"),
                    log_text=lg.get("message") or lg.get("log", "") or "",
                    job_identifier=lg.get("jobIdentifier", ""),
                    integration=lg.get("integration", ""),
                    job_instance_id=lg.get("jobInstanceId", job_instance_id),
                    raw=lg,
                )
            )

        return results


class UpdateJobWorkflow:
    """Updates a SOAR scheduled job definition and optionally syncs script changes to its active job instances."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
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
        payload: Dict[str, Any] = {}
        mask_fields: List[str] = []

        if script is not None:
            payload["script"] = script
            mask_fields.append("script")
        if description is not None:
            payload["description"] = description
            mask_fields.append("description")
        if enabled is not None:
            payload["enabled"] = bool(enabled)
            mask_fields.append("enabled")
        if parameters is not None:
            payload["parameters"] = parameters
            mask_fields.append("parameters")

        final_mask = update_mask or ",".join(mask_fields) or "script"
        updated_job = self.adapter.update_job(
            integration=integration,
            job_id=job_id,
            job_payload=payload,
            update_mask=final_mask,
        )

        synced_instances: List[Dict[str, Any]] = []
        if sync_instances and script is not None:
            raw_instances = self.adapter.list_job_instances(
                integration=integration,
                job_id=job_id,
                page_size=100,
            )
            for inst in raw_instances:
                inst_name = inst.get("name", "")
                inst_id = str(inst.get("id")) if inst.get("id") else _parse_job_instance_id_from_name(inst_name)
                if inst_id:
                    res_inst = self.adapter.update_job_instance(
                        integration=integration,
                        job_id=job_id,
                        instance_id=inst_id,
                        instance_payload={"script": script},
                        update_mask="script",
                    )
                    synced_instances.append(res_inst)

        return {
            "job": updated_job,
            "synced_instances": synced_instances,
            "synced_instance_count": len(synced_instances),
        }


class UpdateJobInstanceWorkflow:
    """Updates a configured runtime SOAR job instance (script, schedule, parameters, or enabled status)."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
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
        payload: Dict[str, Any] = {}
        mask_fields: List[str] = []

        if script is not None:
            payload["script"] = script
            mask_fields.append("script")
        if enabled is not None:
            payload["enabled"] = bool(enabled)
            mask_fields.append("enabled")
        if interval_seconds is not None:
            payload["intervalSeconds"] = int(interval_seconds)
            mask_fields.append("intervalSeconds")
        if parameters is not None:
            payload["parameters"] = parameters
            mask_fields.append("parameters")
        if advanced_config is not None:
            payload["advancedConfig"] = advanced_config
            mask_fields.append("advancedConfig")

        final_mask = update_mask or ",".join(mask_fields) or "script"
        return self.adapter.update_job_instance(
            integration=integration,
            job_id=job_id,
            instance_id=instance_id,
            instance_payload=payload,
            update_mask=final_mask,
        )


class CreateJobInstanceWorkflow:
    """Creates a new scheduled runtime SOAR job instance for a job definition."""

    def __init__(self, adapter: Any):
        self.adapter = adapter

    def execute(
        self,
        integration: str,
        job_id: str,
        instance_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if not isinstance(instance_payload, dict) or not instance_payload:
            raise ValueError("instance_payload must be a non-empty dictionary.")
        return self.adapter.create_job_instance(
            integration=integration,
            job_id=job_id,
            instance_payload=instance_payload,
        )

