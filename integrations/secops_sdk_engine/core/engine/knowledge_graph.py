"""Builds the OKF knowledge graph (nodes, edges, bodies) from ``knowledge/``.

Used by:
- ``clients/web/server.py`` — on-demand ``/knowledge/viz.html`` and
  ``/api/knowledge/graph``, cached until any ``knowledge/**/*.md`` changes.
- ``scripts/generate_knowledge_graph.py`` — CLI export of a standalone HTML file.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from engine.okf import OKFDocument, is_stale, normalize_verified, trust_tier

DEFAULT_KNOWLEDGE_ROOT = Path(__file__).resolve().parent.parent / "knowledge"

_LINK_RE = re.compile(r"\]\(([^)\s]+\.md)(?:#[A-Za-z0-9_\-]*)?\)")

_TYPE_PALETTE = {
    "concept": "#8b5cf6",
    "feature": "#3b82f6",
    "persona": "#f59e0b",
    "task": "#10b981",
    "computation": "#ef4444",
}
# Legacy / alias frontmatter types folded into a canonical display type.
_TYPE_ALIASES = {
    "attested computation": "computation",
}
_DEFAULT_NODE_COLOR = "#94a3b8"


def _canonical_type(raw: Any) -> str:
    t = str(raw or "concept").strip()
    return _TYPE_ALIASES.get(t.lower(), t.lower())


def _as_str_list(val: Any) -> List[str]:
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _skip(md_path: Path) -> bool:
    return md_path.name in ("index.md", "README.md") or "templates" in md_path.parts


def knowledge_fingerprint(knowledge_root: Path) -> Tuple[Tuple[str, int, int], ...]:
    """Cheap change detector: (relpath, mtime_ns, size) for every graph source file."""
    if not knowledge_root.is_dir():
        return ()
    out = []
    for md_path in sorted(knowledge_root.rglob("*.md")):
        if _skip(md_path):
            continue
        try:
            st = md_path.stat()
        except OSError:
            continue
        out.append((md_path.relative_to(knowledge_root).as_posix(), st.st_mtime_ns, st.st_size))
    return tuple(out)


@dataclass
class KnowledgeNode:
    id: str
    doc_id: str
    type: str
    title: str
    description: str
    resource: str
    tags: List[str]
    body: str
    status: str = "stable"
    generated: Dict[str, Any] = field(default_factory=dict)
    verified: List[Dict[str, Any]] = field(default_factory=list)
    stale_after: str = ""
    sources: List[Dict[str, Any]] = field(default_factory=list)
    trust_tier: str = "unverified"
    stale: bool = False
    capabilities: List[str] = field(default_factory=list)
    links_to: List[str] = field(default_factory=list)

    def to_cytoscape_node(self) -> Dict[str, Any]:
        color = _TYPE_PALETTE.get(self.type, _DEFAULT_NODE_COLOR)
        return {
            "data": {
                "id": self.id,
                "label": self.title or self.id,
                "type": self.type,
                "description": self.description,
                "resource": self.resource,
                "tags": self.tags,
                "status": self.status,
                "generated": self.generated,
                "verified": self.verified,
                "stale_after": self.stale_after,
                "sources": self.sources,
                "trust_tier": self.trust_tier,
                "stale": self.stale,
                "capabilities": self.capabilities,
                "color": color,
                "size": 32 + min(50, len(self.body) // 250),
            }
        }


def _extract_body_links(body: str, doc_dir: Path, knowledge_root: Path) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    knowledge_root_resolved = knowledge_root.resolve()
    for m in _LINK_RE.finditer(body):
        target = m.group(1)
        if "://" in target or target.startswith("/"):
            continue
        try:
            resolved = (doc_dir / target).resolve().relative_to(knowledge_root_resolved)
        except ValueError:
            continue
        rel = resolved.as_posix()
        if rel.endswith(".md"):
            rel = rel[:-3]
        if rel and rel not in seen:
            seen.add(rel)
            out.append(rel)
    return out


def load_knowledge_nodes(knowledge_root: Path) -> Tuple[List[KnowledgeNode], Dict[str, str]]:
    nodes: List[KnowledgeNode] = []
    id_to_node_key: Dict[str, str] = {}  # doc_id (e.g. concept.udm_search_lifecycle) -> node_key
    frontmatters: Dict[str, Dict[str, Any]] = {}

    if not knowledge_root.is_dir():
        return nodes, id_to_node_key

    # Pass 1: discover nodes and index IDs
    for md_path in sorted(knowledge_root.rglob("*.md")):
        if _skip(md_path):
            continue
        rel = md_path.relative_to(knowledge_root).with_suffix("")
        node_key = "/".join(rel.parts)

        try:
            doc = OKFDocument.load(md_path)
        except Exception:
            continue

        fm = doc.frontmatter
        frontmatters[node_key] = fm
        doc_id = str(fm.get("id") or node_key)
        id_to_node_key[doc_id] = node_key
        id_to_node_key[node_key] = node_key

        tags = fm.get("tags") or []
        if not isinstance(tags, list):
            tags = [str(tags)]

        node = KnowledgeNode(
            id=node_key,
            doc_id=doc_id,
            type=_canonical_type(fm.get("type")),
            title=str(fm.get("title") or node_key),
            description=str(fm.get("description") or ""),
            resource=str(fm.get("resource") or ""),
            tags=[str(t) for t in tags],
            body=doc.body or "",
            status=str(fm.get("status") or "stable"),
            generated=fm.get("generated") if isinstance(fm.get("generated"), dict) else {},
            verified=normalize_verified(fm),
            stale_after=str(fm.get("stale_after") or ""),
            sources=fm.get("sources") if isinstance(fm.get("sources"), list) else [],
            trust_tier=trust_tier(fm),
            stale=is_stale(fm),
            capabilities=_as_str_list(fm.get("capabilities_used") or fm.get("sdk_capabilities")),
            links_to=_extract_body_links(doc.body or "", md_path.parent, knowledge_root),
        )
        nodes.append(node)

    # Pass 2: supplement links with frontmatter relations
    for node in nodes:
        fm = frontmatters.get(node.id, {})
        relations: List[str] = []
        for k in ("related_concepts", "related_features", "primary_tasks"):
            val = fm.get(k)
            if isinstance(val, list):
                relations.extend(str(v) for v in val)
        p = fm.get("persona")
        if p:
            relations.append(str(p))
        for r in relations:
            target_key = id_to_node_key.get(r)
            if target_key and target_key != node.id and target_key not in node.links_to:
                node.links_to.append(target_key)

    return nodes, id_to_node_key


def build_graph_data(nodes: List[KnowledgeNode]) -> Dict[str, Any]:
    all_ids = {n.id for n in nodes}
    cy_nodes = [n.to_cytoscape_node() for n in nodes]
    edges: List[Dict[str, Any]] = []
    seen_edges: Set[Tuple[str, str]] = set()

    for n in nodes:
        for target in n.links_to:
            if target == n.id or target not in all_ids:
                continue
            key = (n.id, target)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append({
                "data": {
                    "id": f"{n.id}__{target}",
                    "source": n.id,
                    "target": target,
                    "kind": "links",
                }
            })

    bodies = {n.id: n.body for n in nodes}
    types = sorted({n.type for n in nodes})
    return {
        "nodes": cy_nodes,
        "edges": edges,
        "bodies": bodies,
        "types": types,
        "palette": _TYPE_PALETTE,
    }


def _script_safe_json(obj: Any) -> str:
    """JSON for embedding inside <script>: prevents '</script>' / HTML-comment breakout."""
    return (
        json.dumps(obj, default=str)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html(graph_data: Dict[str, Any], bundle_name: str = "Google SecOps Engine Knowledge Base") -> str:
    """Render single self-contained HTML page with Cytoscape and Marked.js."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{bundle_name} — OKF Graph Viewer</title>
<script src="https://cdn.jsdelivr.net/npm/cytoscape@3.28.1/dist/cytoscape.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked@12.0.0/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"></script>
<style>
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, system-ui, sans-serif;
  font-size: 14px;
  color: #0f172a;
  background: #f8fafc;
  display: flex;
  flex-direction: column;
  height: 100vh;
}}
body > header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  background: #1e293b;
  color: #f8fafc;
  border-bottom: 1px solid #334155;
  flex-shrink: 0;
}}
.title strong {{ font-size: 16px; margin-right: 8px; color: #38bdf8; }}
.muted {{ color: #94a3b8; font-size: 12px; }}
.controls {{ display: flex; gap: 8px; }}
.controls input, .controls select, .controls button {{
  font-size: 13px;
  padding: 6px 10px;
  border: 1px solid #475569;
  border-radius: 6px;
  background: #0f172a;
  color: #f8fafc;
}}
.controls input {{ width: 240px; }}
.controls button {{ cursor: pointer; background: #334155; }}
.controls button:hover {{ background: #475569; }}

main {{
  display: flex;
  flex: 1;
  min-height: 0;
}}
#graph {{
  flex: 1 1 65%;
  background: #0b0f19;
  border-right: 1px solid #1e293b;
  min-width: 0;
  position: relative;
}}
#detail {{
  flex: 0 0 35%;
  overflow-y: auto;
  padding: 20px 24px;
  background: #ffffff;
  color: #0f172a;
}}
#detail-empty {{
  text-align: center;
  margin-top: 50px;
  color: #64748b;
}}

.detail-header {{ margin-bottom: 14px; }}
.detail-header h1 {{
  font-size: 20px;
  margin: 6px 0 4px;
  font-weight: 700;
  color: #0f172a;
}}
.type-chip {{
  display: inline-block;
  padding: 3px 9px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  background: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.trust-badge {{
  display: inline-block;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  margin-left: 6px;
}}
.trust-human {{ background: #dcfce7; color: #166534; border: 1px solid #86efac; }}
.trust-machine {{ background: #e0f2fe; color: #075985; border: 1px solid #7dd3fc; }}
.trust-unverified {{ background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }}

dl.frontmatter {{
  display: grid;
  grid-template-columns: 100px 1fr;
  row-gap: 6px;
  column-gap: 12px;
  margin: 12px 0 16px;
  font-size: 13px;
  background: #f1f5f9;
  padding: 12px;
  border-radius: 8px;
}}
dl.frontmatter dt {{
  color: #475569;
  font-weight: 600;
}}
dl.frontmatter dd {{
  margin: 0;
  word-break: break-all;
}}
#detail-body {{
  line-height: 1.6;
  font-size: 14px;
}}
#detail-body pre {{
  background: #0f172a;
  color: #f8fafc;
  padding: 12px;
  border-radius: 6px;
  overflow-x: auto;
}}
#detail-body code {{
  background: #f1f5f9;
  padding: 2px 5px;
  border-radius: 4px;
  font-size: 13px;
}}
#detail-body pre code {{
  background: transparent;
  padding: 0;
}}
.tag-badge {{
  display: inline-block;
  background: #e2e8f0;
  color: #334155;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 11px;
  margin-right: 4px;
}}
</style>
</head>
<body>
<header>
  <div class="title">
    <strong>{bundle_name}</strong>
    <span class="muted">OKF v0.2 Knowledge Graph</span>
  </div>
  <div class="controls">
    <input id="search" type="search" placeholder="Search title / id / tag...">
    <select id="filter-type">
      <option value="">All Types ({len(graph_data["nodes"])} items)</option>
    </select>
    <select id="layout">
      <option value="cose">cose (force layout)</option>
      <option value="concentric">concentric</option>
      <option value="breadthfirst">breadth-first</option>
      <option value="circle">circle</option>
      <option value="grid">grid</option>
    </select>
    <button id="reset">Reset View</button>
  </div>
</header>

<main>
  <section id="graph"></section>
  <section id="detail">
    <div id="detail-empty">
      <svg width="48" height="48" fill="none" stroke="currentColor" viewBox="0 0 24 24" style="margin-bottom:8px; opacity:0.6;"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
      <div>Click any node in the graph to inspect its OKF v0.2 frontmatter, verification status, and runbook content.</div>
    </div>
    <article id="detail-content" style="display:none;">
      <header class="detail-header">
        <span class="type-chip" id="detail-type"></span>
        <span class="trust-badge" id="detail-trust"></span>
        <h1 id="detail-title"></h1>
        <div class="muted" id="detail-id"></div>
      </header>
      <dl class="frontmatter">
        <dt>Description</dt><dd id="detail-desc"></dd>
        <dt>Tags</dt><dd id="detail-tags"></dd>
        <dt>Status</dt><dd id="detail-status"></dd>
        <dt>Stale After</dt><dd id="detail-stale"></dd>
        <dt>Generated</dt><dd id="detail-gen"></dd>
        <dt>Verified</dt><dd id="detail-ver"></dd>
        <dt>Sources</dt><dd id="detail-src"></dd>
      </dl>
      <hr style="border:0; border-top:1px solid #e2e8f0; margin:16px 0;">
      <div id="detail-body"></div>
    </article>
  </section>
</main>

<script>
window.GRAPH_DATA = {_script_safe_json(graph_data)};
(function() {{
  const data = window.GRAPH_DATA;
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}})[c]);
  const safeUrl = u => /^https?:\/\//i.test(String(u || "")) ? u : "#";
  const typeSelect = document.getElementById("filter-type");
  for (const t of data.types) {{
    const opt = document.createElement("option");
    opt.value = t;
    opt.textContent = t.toUpperCase();
    typeSelect.appendChild(opt);
  }}

  const cy = cytoscape({{
    container: document.getElementById("graph"),
    elements: [...data.nodes, ...data.edges],
    style: [
      {{
        selector: "node",
        style: {{
          "background-color": "data(color)",
          "label": "data(label)",
          "color": "#f8fafc",
          "font-size": 11,
          "text-valign": "bottom",
          "text-margin-y": 5,
          "text-wrap": "wrap",
          "text-max-width": 110,
          "width": "data(size)",
          "height": "data(size)",
          "border-width": 2,
          "border-color": "#ffffff",
          "text-background-color": "#0b0f19",
          "text-background-opacity": 0.8,
          "text-background-padding": 2,
          "text-background-shape": "roundrectangle"
        }}
      }},
      {{
        selector: "node:selected",
        style: {{
          "border-width": 4,
          "border-color": "#38bdf8",
          "width": "mapData(size, 20, 80, 35, 95)",
          "height": "mapData(size, 20, 80, 35, 95)"
        }}
      }},
      {{
        selector: "edge",
        style: {{
          "width": 1.5,
          "line-color": "#475569",
          "target-arrow-color": "#475569",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.8
        }}
      }},
      {{
        selector: "edge:selected",
        style: {{
          "line-color": "#38bdf8",
          "target-arrow-color": "#38bdf8",
          "width": 2.5
        }}
      }}
    ],
    layout: {{ name: "cose", padding: 30, animate: false }}
  }});

  function showDetail(node) {{
    const d = node.data();
    document.getElementById("detail-empty").style.display = "none";
    const cont = document.getElementById("detail-content");
    cont.style.display = "block";

    document.getElementById("detail-type").textContent = d.type;
    document.getElementById("detail-type").style.backgroundColor = d.color;
    document.getElementById("detail-title").textContent = d.label;
    document.getElementById("detail-id").textContent = d.id;
    document.getElementById("detail-desc").textContent = d.description || "—";
    
    // Trust badge
    const trustEl = document.getElementById("detail-trust");
    trustEl.textContent = d.trust_tier.toUpperCase();
    trustEl.className = "trust-badge trust-" + (d.trust_tier === "human-reviewed" ? "human" : d.trust_tier === "machine-confirmed" ? "machine" : "unverified");

    // Tags
    const tagsEl = document.getElementById("detail-tags");
    tagsEl.innerHTML = (d.tags || []).map(t => `<span class="tag-badge">${{esc(t)}}</span>`).join("") || "—";

    document.getElementById("detail-status").textContent = d.status || "stable";
    document.getElementById("detail-stale").textContent = d.stale_after || "—";
    
    // Generated
    const gen = d.generated;
    document.getElementById("detail-gen").textContent = gen && gen.by ? `${{gen.by}} (${{gen.at || ""}})` : "—";

    // Verified
    const ver = d.verified;
    document.getElementById("detail-ver").textContent = ver && ver.length ? ver.map(v => `${{v.by}} (${{v.at || ""}})`).join(", ") : "Unverified";

    // Sources
    const src = d.sources;
    document.getElementById("detail-src").innerHTML = src && src.length ? src.map(s => `<a href="${{esc(safeUrl(s.resource))}}" target="_blank" rel="noopener">${{esc(s.title || s.resource)}}</a>`).join("<br>") : "—";

    // Markdown body
    const bodyMarkdown = data.bodies[d.id] || "";
    document.getElementById("detail-body").innerHTML = window.DOMPurify ? DOMPurify.sanitize(marked.parse(bodyMarkdown)) : esc(bodyMarkdown).replace(/\n/g, "<br>");
  }}

  window.cy = cy;
  window.showDetail = showDetail;

  cy.on("tap", "node", e => showDetail(e.target));

  // Auto-select the most-connected node on load
  if (cy.nodes().length) {{
    const first = cy.nodes().max(n => n.degree()).ele;
    first.select();
    showDetail(first);
  }}

  // Search + type filters (combined)
  const searchEl = document.getElementById("search");
  function applyFilters() {{
    const q = searchEl.value.toLowerCase().trim();
    const t = typeSelect.value;
    cy.nodes().forEach(n => {{
      const d = n.data();
      const typeOk = !t || d.type === t;
      const textOk = !q || d.label.toLowerCase().includes(q) || d.id.toLowerCase().includes(q) || (d.tags || []).some(x => x.toLowerCase().includes(q));
      (typeOk && textOk) ? n.show() : n.hide();
    }});
  }}
  searchEl.addEventListener("input", applyFilters);
  typeSelect.addEventListener("change", applyFilters);

  // Layout change
  document.getElementById("layout").addEventListener("change", e => {{
    cy.layout({{ name: e.target.value, animate: true, animationDuration: 500 }}).run();
  }});

  // Reset view
  document.getElementById("reset").addEventListener("click", () => {{
    cy.fit(null, 30);
  }});
}})();
</script>
</body>
</html>
"""


def overlay_agents(graph: Dict[str, Any], agents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a copy of ``graph`` with an agent layer added.

    Each agent dict needs ``handle`` and ``capabilities``; ``name``, ``role``,
    ``subsystem``, ``description`` are passed through for display. An agent
    ``uses`` a knowledge doc when they share at least one capability (the same
    rule SkillCatalog grounding uses). The input graph is not mutated.
    """
    doc_caps = {
        n["data"]["id"]: set(n["data"].get("capabilities") or [])
        for n in graph["nodes"]
    }
    agent_nodes: List[Dict[str, Any]] = []
    agent_edges: List[Dict[str, Any]] = []
    for a in sorted(agents, key=lambda x: x.get("handle", "")):
        handle = str(a.get("handle") or "")
        if not handle:
            continue
        caps = set(a.get("capabilities") or [])
        node_id = f"agent:{handle}"
        uses = []
        for doc_id, dcaps in doc_caps.items():
            shared = sorted(caps & dcaps)
            if shared:
                uses.append(doc_id)
                agent_edges.append({
                    "data": {
                        "id": f"{node_id}__{doc_id}",
                        "source": node_id,
                        "target": doc_id,
                        "kind": "uses",
                        "via": shared,
                    }
                })
        agent_nodes.append({
            "data": {
                "id": node_id,
                "label": handle,
                "type": "agent",
                "handle": handle,
                "name": str(a.get("name") or handle),
                "role": str(a.get("role") or ""),
                "subsystem": str(a.get("subsystem") or ""),
                "description": str(a.get("description") or ""),
                "capabilities": sorted(caps),
                "uses": uses,
                "tags": [str(a.get("subsystem") or "")] if a.get("subsystem") else [],
            }
        })
    out = dict(graph)
    out["nodes"] = list(graph["nodes"]) + agent_nodes
    out["edges"] = list(graph["edges"]) + agent_edges
    types = set(graph.get("types") or [])
    if agent_nodes:
        types.add("agent")
    out["types"] = sorted(types)
    return out


def build_graph(knowledge_root: Path = DEFAULT_KNOWLEDGE_ROOT) -> Dict[str, Any]:
    nodes, _ = load_knowledge_nodes(knowledge_root)
    return build_graph_data(nodes)


class KnowledgeGraphCache:
    """Thread-safe cache of graph data / rendered HTML, rebuilt when sources change."""

    def __init__(self, knowledge_root: Path = DEFAULT_KNOWLEDGE_ROOT):
        self.knowledge_root = knowledge_root
        self._lock = threading.Lock()
        self._fingerprint: Optional[Tuple[Tuple[str, int, int], ...]] = None
        self._graph: Optional[Dict[str, Any]] = None
        self._html: Optional[str] = None

    def _refresh_locked(self) -> None:
        fp = knowledge_fingerprint(self.knowledge_root)
        if self._graph is None or fp != self._fingerprint:
            self._graph = build_graph(self.knowledge_root)
            self._html = None
            self._fingerprint = fp

    def graph(self) -> Dict[str, Any]:
        with self._lock:
            self._refresh_locked()
            return self._graph  # type: ignore[return-value]

    def html(self) -> str:
        with self._lock:
            self._refresh_locked()
            if self._html is None:
                self._html = render_html(self._graph)  # type: ignore[arg-type]
            return self._html
