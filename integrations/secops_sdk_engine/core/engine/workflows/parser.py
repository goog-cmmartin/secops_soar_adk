"""Parsers, Log Types, Extensions and Settings Workflows (Milestone 5.11).

Orchestrates SIEM parser discovery, deep CBN Logstash code resolution,
parser extension analysis, and autonomous parsing configuration.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from adapters.google_secops import GoogleSecOpsAdapter
from engine.domain import (
    LogTypeBatch,
    LogTypeSetting,
    LogTypeSummary,
    ParserBatch,
    ParserDetail,
    ParserExtensionBatch,
    ParserExtensionDetail,
    ParserExtensionSummary,
    ParserRunResult,
    ParserRunResultEntry,
    ParserSummary,
    UnparsedLogDiagnostic,
    UnparsedLogsDiagnosticBatch,
)


class ListLogTypesWorkflow:
    """Discovers and filters supported ingestion log types."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, query: str = "", limit: int = 100) -> LogTypeBatch:
        items: List[Dict[str, Any]] = []
        page_token = None
        last_next_page_token = None

        # Fetch pages: if filtering by query, continue until exhausted or max 10 pages;
        # if not filtering by query, fetch until limit is satisfied or max 3 pages.
        max_pages = 10 if query else 2
        pages_fetched = 0

        while pages_fetched < max_pages:
            raw_res = self.adapter.list_log_types(page_size=1000, page_token=page_token)
            page_items = raw_res.get("logTypes", [])
            items.extend(page_items)
            last_next_page_token = raw_res.get("nextPageToken")
            pages_fetched += 1

            if not last_next_page_token or not page_items:
                break
            if not query and len(items) >= limit:
                break
            page_token = last_next_page_token

        summaries: List[LogTypeSummary] = []
        for it in items:
            name = it.get("name", "")
            lt_id = name.split("/")[-1] if "/" in name else name
            disp = it.get("displayName", lt_id)

            if query:
                q_lower = query.lower()
                if q_lower not in lt_id.lower() and q_lower not in disp.lower():
                    continue

            summaries.append(
                LogTypeSummary(
                    name=name,
                    id=lt_id,
                    display_name=disp,
                    raw=it,
                )
            )

        total_count = len(summaries)
        limited = summaries[:limit]
        return LogTypeBatch(
            log_types=limited,
            total_count=total_count,
            next_page_token=last_next_page_token,
        )


class SearchParsersWorkflow:
    """Discovers and filters parsers across log types."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        log_type: str = "-",
        creator: str = "ALL",
        state: str = "ALL",
        query: str = "",
        limit: int = 50,
    ) -> ParserBatch:
        raw_res = self.adapter.list_parsers(log_type=log_type, view="BASIC_VIEW", page_size=1000)
        items = raw_res.get("parsers", [])

        summaries: List[ParserSummary] = []
        for it in items:
            name = it.get("name", "")
            # e.g. projects/.../logTypes/A10_LOAD_BALANCER/parsers/2354171355617820673
            parts = name.split("/")
            lt = ""
            parser_id = parts[-1] if parts else ""
            if "logTypes" in parts:
                lt_idx = parts.index("logTypes")
                if lt_idx + 1 < len(parts):
                    lt = parts[lt_idx + 1]

            creator_obj = it.get("creator", {})
            c_src = creator_obj.get("source", "UNKNOWN")

            if creator != "ALL" and c_src.upper() != creator.upper():
                continue

            p_state = it.get("state", "UNKNOWN")
            if state != "ALL" and p_state.upper() != state.upper():
                continue

            vinfo = it.get("versionInfo", {})
            ver = vinfo.get("version", "")
            latest_ver = vinfo.get("latestParserVersion", ver)
            rollback = vinfo.get("rollbackAvailable", False)

            if query:
                q_lower = query.lower()
                if q_lower not in parser_id.lower() and q_lower not in lt.lower():
                    continue

            summaries.append(
                ParserSummary(
                    name=name,
                    id=parser_id,
                    log_type=lt,
                    creator_source=c_src,
                    create_time=it.get("createTime", ""),
                    type=it.get("type", "UNKNOWN"),
                    state=p_state,
                    release_stage=it.get("releaseStage", "UNKNOWN"),
                    version=ver,
                    latest_version=latest_ver,
                    rollback_available=rollback,
                    raw=it,
                )
            )

        total_count = len(summaries)
        limited = summaries[:limit]
        return ParserBatch(
            parsers=limited,
            total_count=total_count,
            next_page_token=raw_res.get("nextPageToken"),
        )


class GetParserDetailWorkflow:
    """Retrieves full parser metadata and decodes CBN Logstash filter code."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, log_type: str, parser_id: Optional[str] = None) -> ParserDetail:
        clean_lt = log_type.split("/")[-1]
        raw_parser: Dict[str, Any]

        if parser_id:
            raw_parser = self.adapter.get_parser(clean_lt, parser_id, view="FULL_VIEW")
        else:
            # Query all parsers for log type and select active or first
            raw_res = self.adapter.list_parsers(log_type=clean_lt, view="FULL_VIEW", page_size=1000)
            parsers = raw_res.get("parsers", [])
            if not parsers:
                raise ValueError(f"No parsers found for log type '{clean_lt}'")
            active_p = next((p for p in parsers if p.get("state") == "ACTIVE"), parsers[0])
            raw_parser = active_p

        name = raw_parser.get("name", "")
        parts = name.split("/")
        p_id = parts[-1] if parts else ""
        if "logTypes" in parts:
            lt_idx = parts.index("logTypes")
            if lt_idx + 1 < len(parts):
                clean_lt = parts[lt_idx + 1]

        creator_obj = raw_parser.get("creator", {})
        c_src = creator_obj.get("source", "UNKNOWN")
        vinfo = raw_parser.get("versionInfo", {})
        ver = vinfo.get("version", "")
        latest_ver = vinfo.get("latestParserVersion", ver)
        rollback = vinfo.get("rollbackAvailable", False)

        summary = ParserSummary(
            name=name,
            id=p_id,
            log_type=clean_lt,
            creator_source=c_src,
            create_time=raw_parser.get("createTime", ""),
            type=raw_parser.get("type", "UNKNOWN"),
            state=raw_parser.get("state", "UNKNOWN"),
            release_stage=raw_parser.get("releaseStage", "UNKNOWN"),
            version=ver,
            latest_version=latest_ver,
            rollback_available=rollback,
            raw=raw_parser,
        )

        cbn_raw = raw_parser.get("cbn")
        cbn_code = None
        if cbn_raw:
            try:
                cbn_code = base64.b64decode(cbn_raw).decode("utf-8")
            except Exception:
                cbn_code = None

        return ParserDetail(
            summary=summary,
            cbn_raw=cbn_raw,
            cbn_code=cbn_code,
            validation_report=raw_parser.get("validationReport"),
            changelogs=raw_parser.get("changelogs", {}),
            creator_details=creator_obj,
            raw=raw_parser,
        )


class SearchParserExtensionsWorkflow:
    """Discovers parser extensions across log types."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        log_type: str = "-",
        query: str = "",
        limit: int = 50,
    ) -> ParserExtensionBatch:
        raw_res = self.adapter.list_parser_extensions(log_type=log_type, page_size=1000)
        items = raw_res.get("parserExtensions", [])

        summaries: List[ParserExtensionSummary] = []
        for it in items:
            name = it.get("name", "")
            # e.g. projects/.../logTypes/CS_EDR/parserExtensions/e0f8e4cf...
            parts = name.split("/")
            lt = ""
            ext_id = parts[-1] if parts else ""
            if "logTypes" in parts:
                lt_idx = parts.index("logTypes")
                if lt_idx + 1 < len(parts):
                    lt = parts[lt_idx + 1]

            dyn = it.get("dynamicParsing", {})
            opted = dyn.get("optedFields", [])
            has_dyn = len(opted) > 0
            has_snippet = bool(it.get("cbnSnippet"))

            if query:
                q_lower = query.lower()
                if q_lower not in ext_id.lower() and q_lower not in lt.lower():
                    continue

            summaries.append(
                ParserExtensionSummary(
                    name=name,
                    id=ext_id,
                    log_type=lt,
                    state=it.get("state", "UNKNOWN"),
                    create_time=it.get("createTime", ""),
                    state_last_changed_time=it.get("stateLastChangedTime", ""),
                    last_live_time=it.get("lastLiveTime"),
                    has_dynamic_parsing=has_dyn,
                    opted_fields_count=len(opted),
                    has_cbn_snippet=has_snippet,
                    raw=it,
                )
            )

        total_count = len(summaries)
        limited = summaries[:limit]
        return ParserExtensionBatch(
            parser_extensions=limited,
            total_count=total_count,
            next_page_token=raw_res.get("nextPageToken"),
        )


class GetParserExtensionDetailWorkflow:
    """Retrieves full parser extension configuration, decoded snippet, and test log."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, log_type: str, extension_id: str) -> ParserExtensionDetail:
        clean_lt = log_type.split("/")[-1]
        clean_ext = extension_id.split("/")[-1]

        raw_ext = self.adapter.get_parser_extension(clean_lt, clean_ext)

        name = raw_ext.get("name", "")
        parts = name.split("/")
        ext_id = parts[-1] if parts else clean_ext
        if "logTypes" in parts:
            lt_idx = parts.index("logTypes")
            if lt_idx + 1 < len(parts):
                clean_lt = parts[lt_idx + 1]

        dyn = raw_ext.get("dynamicParsing", {})
        opted = dyn.get("optedFields", [])
        has_dyn = len(opted) > 0
        has_snippet = bool(raw_ext.get("cbnSnippet"))

        summary = ParserExtensionSummary(
            name=name,
            id=ext_id,
            log_type=clean_lt,
            state=raw_ext.get("state", "UNKNOWN"),
            create_time=raw_ext.get("createTime", ""),
            state_last_changed_time=raw_ext.get("stateLastChangedTime", ""),
            last_live_time=raw_ext.get("lastLiveTime"),
            has_dynamic_parsing=has_dyn,
            opted_fields_count=len(opted),
            has_cbn_snippet=has_snippet,
            raw=raw_ext,
        )

        snippet_raw = raw_ext.get("cbnSnippet")
        snippet_code = None
        if snippet_raw:
            try:
                snippet_code = base64.b64decode(snippet_raw).decode("utf-8")
            except Exception:
                snippet_code = None

        log_raw = raw_ext.get("log")
        sample_log = None
        if log_raw:
            try:
                sample_log = base64.b64decode(log_raw).decode("utf-8")
            except Exception:
                sample_log = None

        return ParserExtensionDetail(
            summary=summary,
            cbn_snippet_raw=snippet_raw,
            cbn_snippet=snippet_code,
            sample_log_raw=log_raw,
            sample_log=sample_log,
            opted_fields=opted,
            validation_report=raw_ext.get("validationReport"),
            extension_validation_report=raw_ext.get("extensionValidationReport"),
            raw=raw_ext,
        )


class GetLogTypeSettingWorkflow:
    """Retrieves autonomous parsing settings for a log type."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(self, log_type: str) -> LogTypeSetting:
        clean_lt = log_type.split("/")[-1]
        raw_res = self.adapter.get_log_type_setting(clean_lt)
        opt_type = raw_res.get("autonomousParsingExtractionType", "UNSPECIFIED")

        return LogTypeSetting(
            log_type=clean_lt,
            autonomous_parsing_extraction_type=opt_type,
            raw_settings=raw_res,
        )


class RunParserWorkflow:
    """Executes a Logstash CBN parser configuration against raw log text."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        log_type: str,
        raw_log_text: str,
        parser_cbn: Optional[str] = None,
    ) -> ParserRunResult:
        clean_lt = log_type.split("/")[-1]

        # If parser_cbn not provided, resolve active parser
        if not parser_cbn:
            get_wf = GetParserDetailWorkflow(self.adapter)
            detail = get_wf.execute(log_type=clean_lt)
            if not detail.cbn_raw:
                raise ValueError(f"Active parser for '{clean_lt}' does not contain CBN configuration code.")
            cbn_b64 = detail.cbn_raw
        else:
            # Check if parser_cbn is already base64, otherwise base64 encode it
            try:
                decoded = base64.b64decode(parser_cbn.encode("utf-8")).decode("utf-8", errors="ignore")
                if "filter" in decoded:
                    cbn_b64 = parser_cbn
                else:
                    cbn_b64 = base64.b64encode(parser_cbn.encode("utf-8")).decode("utf-8")
            except Exception:
                cbn_b64 = base64.b64encode(parser_cbn.encode("utf-8")).decode("utf-8")

        raw_res = self.adapter.run_parser(
            log_type=clean_lt,
            parser_cbn_b64=cbn_b64,
            raw_log_text=raw_log_text,
        )

        entries: List[ParserRunResultEntry] = []
        raw_results = raw_res.get("runParserResults", [])

        error_count = 0
        success_count = 0

        for r in raw_results:
            log_b64 = r.get("log", "")
            try:
                log_text = base64.b64decode(log_b64).decode("utf-8", errors="replace") if log_b64 else raw_log_text
            except Exception:
                log_text = raw_log_text

            err_info = r.get("error")
            err_msg = err_info.get("message") if err_info else None
            is_success = err_msg is None

            if is_success:
                success_count += 1
            else:
                error_count += 1

            parsed_events = r.get("parsedEvents", {})
            events_list = []
            if isinstance(parsed_events, dict):
                events_list = parsed_events.get("event", [parsed_events] if parsed_events else [])
            elif isinstance(parsed_events, list):
                events_list = parsed_events

            entries.append(
                ParserRunResultEntry(
                    log_text=log_text,
                    log_b64=log_b64,
                    is_success=is_success,
                    error_message=err_msg,
                    parsed_events=events_list,
                    raw=r,
                )
            )

        return ParserRunResult(
            log_type=clean_lt,
            entries=entries,
            total_runs=len(entries),
            error_count=error_count,
            success_count=success_count,
            raw=raw_res,
        )


class FindUnparsedLogsAndDiagnoseWorkflow:
    """Finds unparsed raw logs for a log type and runs them against the active parser to diagnose errors."""

    def __init__(self, adapter: GoogleSecOpsAdapter):
        self.adapter = adapter

    def execute(
        self,
        log_type: str,
        lookback_hours: int = 168,
        limit: int = 5,
    ) -> UnparsedLogsDiagnosticBatch:
        clean_lt = log_type.split("/")[-1]

        # 1. Resolve deterministic display name via ListLogTypesWorkflow
        lt_wf = ListLogTypesWorkflow(self.adapter)
        lt_batch = lt_wf.execute(query=clean_lt, limit=100)
        display_name = clean_lt
        for lt_summary in lt_batch.log_types:
            if lt_summary.id.upper() == clean_lt.upper():
                display_name = lt_summary.display_name
                break

        # 2. Get active parser via GetParserDetailWorkflow
        parser_wf = GetParserDetailWorkflow(self.adapter)
        parser_detail = parser_wf.execute(log_type=clean_lt)
        if not parser_detail.cbn_raw:
            raise ValueError(f"No active CBN parser found for log type '{clean_lt}'")

        # 3. Search unparsed raw logs via SearchRawLogsWorkflow
        from engine.workflows.raw_log_search import SearchRawLogsWorkflow
        search_wf = SearchRawLogsWorkflow(self.adapter)
        query = f'raw = /.*/ log_source IN ["{display_name}"] parsed = false'
        search_batch = search_wf.execute(
            query=query,
            lookback_hours=lookback_hours,
            page_size=min(limit, 100),
        )

        diagnostics: List[UnparsedLogDiagnostic] = []
        run_wf = RunParserWorkflow(self.adapter)

        # 4. For each unparsed log match, fetch payload and run parser
        for match in search_batch.matches[:limit]:
            log_payload = self.adapter.get_raw_log(match.id)
            raw_text = log_payload.raw_text

            # Execute parser
            run_res = run_wf.execute(
                log_type=clean_lt,
                raw_log_text=raw_text,
                parser_cbn=parser_detail.cbn_raw,
            )

            error_msg = "Unknown parsing error"
            err_category = "UNKNOWN"

            if run_res.entries and run_res.entries[0].error_message:
                error_msg = run_res.entries[0].error_message
                if "non-signed-integral" in error_msg or "type given" in error_msg:
                    err_category = "TYPE_MISMATCH"
                elif "LOG_PARSING_CBN_ERROR" in error_msg:
                    err_category = "CBN_NORMALIZATION_ERROR"
                elif "empty parse tree" in error_msg:
                    err_category = "EMPTY_PARSE_TREE"
                elif "syntax" in error_msg.lower():
                    err_category = "SYNTAX_ERROR"
                else:
                    err_category = "PARSER_FAILURE"
            elif run_res.success_count > 0:
                error_msg = "Parser succeeded in test run (possible ingestion time / pipeline difference)"
                err_category = "NO_REPRO_IN_TEST"

            diagnostics.append(
                UnparsedLogDiagnostic(
                    log_id=match.id,
                    log_type=clean_lt,
                    display_name=display_name,
                    raw_log_preview=raw_text[:300].strip() if len(raw_text) > 300 else raw_text.strip(),
                    raw_log=raw_text,
                    error_message=error_msg,
                    error_category=err_category,
                    parser_id=parser_detail.summary.id,
                    parser_version=parser_detail.summary.version or "custom",
                    parser_creator=parser_detail.summary.creator_source,
                    raw=run_res.raw,
                )
            )

        return UnparsedLogsDiagnosticBatch(
            log_type=clean_lt,
            display_name=display_name,
            total_unparsed_found=len(search_batch.matches),
            total_diagnosed=len(diagnostics),
            diagnostics=diagnostics,
            active_parser_summary=parser_detail.summary,
        )
