import re
from pathlib import Path
from typing import List, Optional, Tuple, Union
try:
  from google.genai import types
except ImportError:
  types = None

from .config import DEFAULT_GUIDES_DIR, LogJammerConfig, get_genai_client
from .models import LearnResult


SYSTEM_PROMPT = """You are an expert security data engineer and detection engineering specialist.
Your task is to analyze real-world log samples for a security/system log type and generate an exhaustive, highly detailed AI generation guide (Playbook).

The guide will be used by an AI scenario generator to produce realistic, synthetically generated logs for security testing and SIEM rule validation.

Your generated guide must include:
1. **Overview & Log Purpose**: What device, application, or system produces this log? What activities are recorded?
2. **Format Specification**:
   - Classification: Is it JSON, CEF, Syslog (RFC 3164 / RFC 5424), Windows Event XML, Key-Value pairs, or custom delimiters?
   - Delimiters and quoting rules.
3. **Schema Breakdown & Fields**:
   - Header fields and metadata (facility, severity, hostname, process name, process ID).
   - Core body fields, types, and realistic distributions (IP addresses, ports, usernames, file paths, URIs, user agents).
   - Expected status codes, event IDs, action verbs (e.g. ALLOW/DENY, SUCCESS/FAILURE).
4. **Timestamp & Dynamic Time Templating**:
   - Explain the timestamp format used (e.g. ISO 8601, Epoch seconds, Syslog MMM DD HH:MM:SS).
   - Explicitly instruct using relative time template tags: `##$TimeStamp-0d2h15m0s$##`, `##$Epoch-0d1h0m0s$##`, `##$SyslogTime-0d0h30m0s$##`.
5. **Concrete Valid Examples**:
   - Provide 3 to 5 realistic, full log lines representing varied activities (normal user activity, failed login, privilege escalation, firewall block).
6. **Key Constraints & Pitfalls**:
   - Fields that MUST be present for parsers not to fail.
   - Escaping rules for nested strings or JSON.
"""


class PlaybookService:
  """Learns log schemas and manages prompt guides for log generation."""

  def __init__(self, config: Optional[LogJammerConfig] = None):
    self.config = config or LogJammerConfig()
    self._client = None

  @property
  def client(self):
    if self._client is None:
      self._client = get_genai_client(self.config)
    return self._client

  def _preprocess_sample_text(self, raw_text: str) -> str:
    """Unwraps and unescapes textproto/protobuf wrappers if detected.

    Extracts raw logs from `batch.entries.data` or `data: "..."` and unescapes
    JSON/Syslog strings so Gemini analyzes the real log payload.
    """
    cleaned = raw_text.strip()
    if ("data:" in cleaned or "entries {" in cleaned or "batch {" in cleaned) and not (
        cleaned.startswith("{") and cleaned.endswith("}")
    ):
      pattern = r'data:\s*"((?:[^"\\]|\\.)*)"'
      matches = re.findall(pattern, cleaned)
      if matches:
        extracted = []
        for m in matches:
          unescaped = (
              m.replace('\\"', '"')
              .replace("\\\\", "\\")
              .replace("\\n", "\n")
              .replace("\\r", "\r")
              .replace("\\t", "\t")
          )
          if unescaped.strip():
            extracted.append(unescaped.strip())
        if extracted:
          return "\n".join(extracted)
    return raw_text

  def _load_samples(
      self, sample_content: Union[str, Path, List[str]]
  ) -> Tuple[str, int, int]:
    """Load sample content from a file, directory, string, or list.

    Returns:
      Tuple of (formatted_samples_text, total_lines, files_analyzed_count)
    """
    if isinstance(sample_content, Path):
      if sample_content.is_dir():
        # Find all regular non-hidden files, ignoring documentation
        files = [
            f
            for f in sorted(sample_content.glob("**/*"))
            if f.is_file()
            and not f.name.startswith(".")
            and f.name.lower() not in ("readme.md", "metadata.json")
        ]
        if not files:
          raise ValueError(
              f"No valid sample files found in directory '{sample_content}'."
          )

        chunks = []
        total_lines = 0
        for f in files:
          with open(f, "r", encoding="utf-8", errors="ignore") as fp:
            content = self._preprocess_sample_text(fp.read().strip())
          if content:
            total_lines += len(content.splitlines())
            rel_name = f.relative_to(sample_content)
            chunks.append(f"--- Sample File: {rel_name} ---\n{content}")

        if not chunks:
          raise ValueError(
              f"All sample files in directory '{sample_content}' were empty."
          )

        return "\n\n".join(chunks), total_lines, len(chunks)
      else:
        with open(sample_content, "r", encoding="utf-8", errors="ignore") as f:
          content = self._preprocess_sample_text(f.read().strip())
        lines = len(content.splitlines()) if content else 0
        return content, lines, 1
    elif isinstance(sample_content, list):
      text = self._preprocess_sample_text("\n".join(sample_content).strip())
      lines = len(text.splitlines()) if text else 0
      return text, lines, 1
    else:
      text = self._preprocess_sample_text(str(sample_content).strip())
      lines = len(text.splitlines()) if text else 0
      return text, lines, 1

  def learn(
      self,
      log_type: str,
      sample_content: Union[str, Path, List[str]],
      output_dir: Optional[Path] = None,
  ) -> LearnResult:
    """Analyze log samples and generate a comprehensive schema playbook."""
    samples_text, sample_lines, files_count = self._load_samples(sample_content)

    if not samples_text.strip():
      raise ValueError(f"Sample content for log type '{log_type}' is empty.")

    user_prompt = f"""Log Type Name: {log_type}

Here are representative log samples extracted from real systems:
```
{samples_text[:50000]}
```

Generate the comprehensive AI log playbook guide for '{log_type}' following the required structure."""

    try:
      from google.genai import types as genai_types
      gen_config = genai_types.GenerateContentConfig(
          system_instruction=SYSTEM_PROMPT,
          temperature=self.config.temperature,
          top_p=self.config.top_p,
          thinking_config=genai_types.ThinkingConfig(
              thinking_budget=self.config.thinking_budget,
          ),
      )
    except (ImportError, AttributeError):
      gen_config = None

    response = self.client.models.generate_content(
        model=self.config.model,
        contents=user_prompt,
        config=gen_config,
    )

    guide_content = response.text or ""

    # Save to guides directory
    target_dir = output_dir or self.config.guides_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    guide_path = target_dir / f"{log_type}.txt"
    guide_path.parent.mkdir(parents=True, exist_ok=True)

    with open(guide_path, "w", encoding="utf-8") as f:
      f.write(guide_content)

    return LearnResult(
        log_type=log_type,
        guide_content=guide_content,
        guide_path=guide_path,
        sample_count=sample_lines,
        files_analyzed=files_count,
    )

  def _get_search_dirs(self, guides_dir: Optional[Path] = None) -> List[Path]:
    """Resolve directories to search for schema playbooks."""
    dirs: List[Path] = []
    if guides_dir:
      dirs.append(Path(guides_dir))
    else:
      dirs.append(self.config.guides_dir)
      # If using default ~/.logjammer/guides, also look in repository/cwd guides/
      if self.config.guides_dir == DEFAULT_GUIDES_DIR:
        repo_guides = Path(__file__).resolve().parent.parent.parent / "guides"
        cwd_guides = Path.cwd() / "guides"
        for candidate in (cwd_guides, repo_guides):
          if candidate.is_dir() and candidate not in dirs:
            dirs.append(candidate)
    return [d for d in dirs if d.exists()]

  @staticmethod
  def _normalize_key(name: str) -> str:
    """Normalize identifier for flexible matching (e.g. AWS_CLOUDTRAIL -> cloudtrail)."""
    s = name.lower().replace("-", "_").replace("/", "_").strip()
    s = re.sub(r"(_format_reference|_reference|_playbook|_guide)$", "", s)
    s = re.sub(r"(_(logs?|access_logs?|findings|syslog|dns))+$", "", s)
    s = re.sub(r"^(aws_|amazon_)", "", s)
    return s

  def _get_aliases(self, f: Path, search_dir: Path, content_sample: str = "") -> set:
    """Derive possible alias names for a guide file."""
    aliases = set()
    stem = f.stem.lower()
    aliases.add(stem)

    try:
      rel_no_ext = f.relative_to(search_dir).with_suffix("").as_posix().lower()
      aliases.add(rel_no_ext)
      aliases.add(rel_no_ext.replace("/", "_"))
    except ValueError:
      pass

    norm = self._normalize_key(f.stem)
    aliases.add(norm)
    aliases.add(f"aws_{norm}")
    aliases.add(f"aws/{norm}")

    secops_match = re.search(
        r"Official SecOps Log Type:\s*`?([A-Za-z0-9_-]+)`?",
        content_sample,
        re.IGNORECASE,
    )
    if secops_match:
      aliases.add(secops_match.group(1).lower())

    return aliases

  def get_guide(self, log_type: str, guides_dir: Optional[Path] = None) -> Optional[str]:
    """Retrieve the guide text for a specific log type, searching directories recursively."""
    guide_extensions = (".txt", ".md", ".markdown")
    search_dirs = self._get_search_dirs(guides_dir)
    target_clean = log_type.strip()
    norm_target = self._normalize_key(target_clean)

    for search_dir in search_dirs:
      # 1. Direct file match
      for ext in guide_extensions:
        direct = search_dir / f"{target_clean}{ext}"
        if direct.is_file():
          with open(direct, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

      direct_path = search_dir / target_clean
      if direct_path.is_file():
        with open(direct_path, "r", encoding="utf-8", errors="ignore") as f:
          return f.read()

      # 2. Recursive search across all guide files in search_dir
      candidates = [
          p for p in search_dir.rglob("*")
          if p.is_file() and p.suffix.lower() in guide_extensions
      ]

      # Exact stem or relative path match
      for p in candidates:
        rel_no_ext = p.relative_to(search_dir).with_suffix("").as_posix()
        if (
            p.stem.lower() == target_clean.lower()
            or rel_no_ext.lower() == target_clean.lower()
            or rel_no_ext.replace("/", "_").lower() == target_clean.lower()
        ):
          with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

      # Alias or normalized match (e.g. AWS_CLOUDTRAIL, CLOUDTRAIL -> AWS/cloudtrail_log_format_reference.md)
      for p in candidates:
        try:
          with open(p, "r", encoding="utf-8", errors="ignore") as f:
            sample = f.read(500)
        except Exception:
          sample = ""

        aliases = self._get_aliases(p, search_dir, sample)
        if target_clean.lower() in aliases or norm_target in aliases:
          with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    return None

  def list_available_log_types(self, guides_dir: Optional[Path] = None) -> List[str]:
    """List all available log types that have guides across directories."""
    guide_extensions = (".txt", ".md", ".markdown")
    search_dirs = self._get_search_dirs(guides_dir)
    log_types = set()

    for search_dir in search_dirs:
      if not search_dir.exists():
        continue
      for p in search_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in guide_extensions:
          rel = p.relative_to(search_dir).with_suffix("")
          if rel.parent == Path("."):
            log_types.add(p.stem)
          else:
            log_types.add(rel.as_posix())

    return sorted(log_types)
