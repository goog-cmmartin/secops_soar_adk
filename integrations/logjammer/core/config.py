"""Configuration management for Log Jammer OSS (SOAR Integration Edition)."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Optional


_CUR_DIR = Path(__file__).resolve().parent
if (_CUR_DIR / "curated_catalog.json").exists():
  BUNDLED_DATA_DIR = _CUR_DIR
  DEFAULT_GUIDES_DIR = _CUR_DIR
  DEFAULT_RULES_DIR = _CUR_DIR
elif (_CUR_DIR / "data").exists():
  BUNDLED_DATA_DIR = _CUR_DIR / "data"
  DEFAULT_GUIDES_DIR = (_CUR_DIR / "data" / "guides") if (_CUR_DIR / "data" / "guides").exists() else (_CUR_DIR / "data")
  DEFAULT_RULES_DIR = _CUR_DIR / "data"
else:
  BUNDLED_DATA_DIR = _CUR_DIR
  DEFAULT_GUIDES_DIR = _CUR_DIR
  DEFAULT_RULES_DIR = _CUR_DIR

DEFAULT_MODEL = "gemini-3.7-flash"
DEFAULT_VERTEX_LOCATION = "global"
DEFAULT_SCENARIOS_DIR = Path("/tmp/logjammer_scenarios")


@dataclass
class LogJammerConfig:
  """Global configuration for Log Jammer services."""

  api_key: Optional[str] = None
  gti_api_key: Optional[str] = None
  model: str = DEFAULT_MODEL
  guides_dir: Path = field(default_factory=lambda: DEFAULT_GUIDES_DIR)
  scenarios_dir: Path = field(default_factory=lambda: DEFAULT_SCENARIOS_DIR)
  rules_dir: Path = field(default_factory=lambda: DEFAULT_RULES_DIR)
  temperature: float = 0.7
  top_p: float = 0.95
  thinking_budget: int = 2048

  # Google SecOps (Chronicle) settings
  customer_id: Optional[str] = None
  project_id: Optional[str] = None
  region: str = "us"
  credentials_file: Optional[str] = None
  credentials: Optional[object] = None
  use_vertex: bool = False
  vertexai: Optional[bool] = None
  vertex_location: str = DEFAULT_VERTEX_LOCATION

  def __post_init__(self):
    if not self.api_key:
      env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
      if env_key and env_key.strip():
        self.api_key = env_key.strip()

    if not self.gti_api_key:
      env_gti = os.environ.get("GTI_API_KEY") or os.environ.get("VT_API_KEY")
      if env_gti and env_gti.strip():
        self.gti_api_key = env_gti.strip()

    env_model = os.environ.get("LOGJAMMER_MODEL")
    if env_model and env_model.strip():
      self.model = env_model.strip()

    if self.vertexai is None:
      env_vertex = (
          os.environ.get("GOOGLE_GENAI_USE_VERTEXAI")
          or os.environ.get("LOGJAMMER_USE_VERTEXAI")
      )
      if env_vertex and env_vertex.strip():
        self.vertexai = env_vertex.strip().lower() in ("1", "true", "yes", "on")

    if self.vertex_location == DEFAULT_VERTEX_LOCATION:
      env_vloc = (
          os.environ.get("LOGJAMMER_VERTEX_LOCATION")
          or os.environ.get("VERTEX_LOCATION")
          or os.environ.get("GOOGLE_CLOUD_LOCATION")
      )
      if env_vloc and env_vloc.strip():
        self.vertex_location = env_vloc.strip()

    if self.guides_dir == DEFAULT_GUIDES_DIR:
      env_guides = os.environ.get("LOGJAMMER_GUIDES_DIR")
      if env_guides and env_guides.strip():
        self.guides_dir = Path(env_guides.strip())

    if self.scenarios_dir == DEFAULT_SCENARIOS_DIR:
      env_scenarios = os.environ.get("LOGJAMMER_SCENARIOS_DIR")
      if env_scenarios and env_scenarios.strip():
        self.scenarios_dir = Path(env_scenarios.strip())

    if self.rules_dir == DEFAULT_RULES_DIR:
      env_rules = os.environ.get("LOGJAMMER_RULES_DIR")
      if env_rules and env_rules.strip():
        self.rules_dir = Path(env_rules.strip())

    # SecOps environment variables
    if not self.customer_id:
      env_cust = os.environ.get("SECOPS_CUSTOMER_ID") or os.environ.get("CHRONICLE_CUSTOMER_ID")
      if env_cust and env_cust.strip():
        self.customer_id = env_cust.strip()

    if not self.project_id:
      env_proj = (
          os.environ.get("SECOPS_PROJECT_ID")
          or os.environ.get("GOOGLE_CLOUD_PROJECT")
          or os.environ.get("GCP_PROJECT_ID")
      )
      if env_proj and env_proj.strip():
        self.project_id = env_proj.strip()

    env_reg = os.environ.get("SECOPS_REGION") or os.environ.get("CHRONICLE_REGION")
    if env_reg and env_reg.strip():
      self.region = env_reg.strip()

    if not self.credentials_file:
      env_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
      if env_creds and env_creds.strip():
        self.credentials_file = env_creds.strip()

    self.guides_dir = Path(self.guides_dir).expanduser().resolve()
    self.scenarios_dir = Path(self.scenarios_dir).expanduser().resolve()
    self.rules_dir = Path(self.rules_dir).expanduser().resolve()

    self.guides_dir.mkdir(parents=True, exist_ok=True)
    self.scenarios_dir.mkdir(parents=True, exist_ok=True)
    self.rules_dir.mkdir(parents=True, exist_ok=True)


def resolve_vertex_adc(config: Optional[LogJammerConfig] = None) -> tuple[Optional[object], Optional[str]]:
  """Resolve Google Cloud ADC credentials and project ID for Vertex AI."""
  cfg = config or LogJammerConfig()
  project = cfg.project_id
  creds = cfg.credentials

  if creds is None:
    try:
      import google.auth

      scopes = ["https://www.googleapis.com/auth/cloud-platform"]
      if cfg.credentials_file:
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(
            cfg.credentials_file, scopes=scopes
        )
        if not project:
          project = getattr(creds, "project_id", None)
      else:
        creds, adc_project = google.auth.default(scopes=scopes)
        if not project:
          project = adc_project or getattr(creds, "quota_project_id", None)
    except Exception:
      creds = None

  return creds, project


def has_vertex_adc(config: Optional[LogJammerConfig] = None) -> bool:
  """Return True if Vertex AI can be initialized via ADC credentials and a project."""
  cfg = config or LogJammerConfig()
  if cfg.vertexai is False:
    return False
  creds, project = resolve_vertex_adc(cfg)
  return bool(creds and project)


def get_genai_client(config: Optional[LogJammerConfig] = None):
  """Instantiate a Google GenAI client using configuration (Gemini API or Vertex AI)."""
  cfg = config or LogJammerConfig()

  try:
    from google import genai
  except ImportError:
    raise ImportError(
        "The 'google-genai' package is required. "
        "Install it via: pip install google-genai"
    )

  # 1. Direct Gemini API Key
  if cfg.api_key and not cfg.use_vertex and not cfg.vertexai:
    try:
      return genai.Client(api_key=cfg.api_key)
    except Exception as e:
      raise ValueError(
          f"[Pre-flight Validation Failed] Invalid Gemini API key ({e}).\n"
          "Please check your GEMINI_API_KEY configuration."
      ) from None

  # 2. Vertex AI with OAuth2 credentials (WIF, Service Account, or ADC)
  try:
    creds, project = resolve_vertex_adc(cfg)
    location = (
        "global"
        if cfg.model.startswith("gemini-3") or cfg.model.startswith("gemini-4")
        else (cfg.vertex_location or cfg.region or DEFAULT_VERTEX_LOCATION)
    )
    vertex_kwargs = {
        "vertexai": True,
        "project": project or cfg.project_id or os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT_ID"),
        "location": location,
    }
    if creds:
      vertex_kwargs["credentials"] = creds
    return genai.Client(**vertex_kwargs)
  except Exception as e:
    if cfg.api_key:
      return genai.Client(api_key=cfg.api_key)
    raise ValueError(
        f"[Pre-flight Validation Failed] Failed to initialize Gemini / Vertex AI client: {e}.\n"
        "Please provide GEMINI_API_KEY or configure GCP Service Account / Workload Identity credentials."
    ) from None
