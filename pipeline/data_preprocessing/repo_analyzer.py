"""
tools/repo_analyzer.py
=======================
Walk a cloned repository to extract its tech stack, service boundaries, and
OS/platform information. Maps everything to CyberBattleSim property vocabulary.

Usage (standalone):
    python tools/repo_analyzer.py --repo /path/to/cloned/repo --out analysis.json
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ── Property mapping tables ───────────────────────────────────────────────────

# (regex-on-package-name, [properties])  — first match wins per package
PKG_TO_PROPS: List[Tuple[str, List[str]]] = [
    # ── Web frameworks ────────────────────────────────────────────────────────
    (r"express|fastify|koa|hapi|restify|nestjs|sails",     ["WebServer", "NodeJS"]),
    (r"django|flask|fastapi|tornado|starlette|aiohttp",     ["WebServer", "Python"]),
    (r"spring-boot|spring-web|jersey|struts",               ["WebServer", "Java"]),
    (r"rails|sinatra|rack|puma",                            ["WebServer", "Ruby"]),
    (r"nginx|apache-httpd|httpd|caddy|traefik",             ["WebServer", "Linux"]),
    (r"asp\.net|aspnetcore|microsoft\.aspnet|webapi",       ["WebServer", "Windows"]),
    (r"laravel|symfony|slim|lumen",                         ["WebServer", "PHP"]),
    (r"gin|echo|fiber|chi|gorilla",                         ["WebServer", "Golang"]),
    # ── Databases ─────────────────────────────────────────────────────────────
    (r"\bpg\b|postgres|psycopg|asyncpg",                   ["DatabaseServer", "PostgreSQL", "Linux"]),
    (r"mysql|mysqlclient|pymysql|aiomysql",                 ["DatabaseServer", "MySQL", "Linux"]),
    (r"mssql|sqlserver|microsoft\.data\.sqlclient",         ["DatabaseServer", "MSSQLServer", "Windows"]),
    (r"mongodb|mongoose|pymongo|motor",                     ["DatabaseServer", "MongoDB", "Linux"]),
    (r"\bredis\b|ioredis|aioredis",                         ["DatabaseServer", "Redis", "Linux"]),
    (r"elasticsearch|opensearch|elastic",                   ["DatabaseServer", "Elasticsearch", "Linux"]),
    (r"\bsqlite\b",                                         ["DatabaseServer", "SQLite"]),
    (r"cassandra|scylla",                                   ["DatabaseServer", "Linux"]),
    # ── Identity / directory ──────────────────────────────────────────────────
    (r"keycloak|okta|auth0|onelogin",                       ["AuthServer", "Linux"]),
    (r"\bldap\b|active.directory|winldap|ldap3",            ["DomainController", "Windows", "LDAP"]),
    (r"kerberos|krb5|gssapi",                               ["DomainController", "Kerberoastable", "Windows"]),
    (r"samba|winbind",                                      ["DomainController", "Windows"]),
    # ── File services ─────────────────────────────────────────────────────────
    (r"\bsamba\b|smb|cifs|winbind",                         ["FileServer", "SMBv1", "Linux"]),
    (r"ftp|vsftpd|proftpd|pure-ftpd",                       ["FileServer", "Linux"]),
    (r"minio|s3fs|boto3",                                   ["FileServer", "Linux"]),
    # ── Remote access ─────────────────────────────────────────────────────────
    (r"openssh|paramiko|asyncssh|fabric",                   ["SSH", "Linux"]),
    (r"\brdp\b|freerdp|xrdp|mstsc",                         ["RDP", "Windows"]),
    (r"\bwinrm\b|pywinrm",                                   ["Windows", "WinRM"]),
    # ── Message queues ────────────────────────────────────────────────────────
    (r"rabbitmq|amqp|pika|aio-pika",                         ["WorkerNode", "Linux"]),
    (r"kafka|confluent|aiokafka",                            ["WorkerNode", "Linux"]),
    (r"celery|dramatiq|rq\b",                                ["WorkerNode", "Linux"]),
    # ── Famous CVE packages ───────────────────────────────────────────────────
    (r"log4j|log4j-core|log4j2",                            ["Log4Shell", "Java", "Unpatched"]),
    (r"apache-struts",                                       ["Java", "Unpatched"]),
    (r"\bopenssl\b",                                         ["Linux", "Unpatched"]),
    (r"shellshock|bash.*4\.[01234]",                         ["Linux", "Unpatched"]),
    (r"eternal.?blue|ms17-010",                             ["Windows", "SMBv1", "Unpatched"]),
    (r"log4shell|jndi",                                      ["Log4Shell", "Unpatched"]),
    # ── Workstation indicators ────────────────────────────────────────────────
    (r"electron|tauri",                                      ["Workstation", "Windows", "Win10"]),
    (r"gtk|qt\b|wxpython",                                   ["Workstation", "Linux"]),
    # ── Platform / language ───────────────────────────────────────────────────
    (r"nodejs|node\.js",                                     ["NodeJS"]),
    (r"^python$|^pip$",                                      ["Python"]),
    (r"\bjava\b|jdk|jre|maven|gradle",                      ["Java"]),
    (r"dotnet|\.net|nuget",                                  ["Windows"]),
    (r"\bruby\b|\bgem\b",                                    ["Ruby", "Linux"]),
    (r"^php$|composer",                                      ["PHP", "Linux"]),
    (r"golang|go\.mod",                                      ["Golang", "Linux"]),
    (r"^rust$|cargo",                                        ["Rust", "Linux"]),
]

# Docker image name → properties
IMAGE_TO_PROPS: Dict[str, List[str]] = {
    "ubuntu":                       ["Linux", "Ubuntu"],
    "debian":                       ["Linux"],
    "alpine":                       ["Linux"],
    "centos":                       ["Linux"],
    "rhel":                         ["Linux"],
    "node":                         ["Linux", "NodeJS"],
    "python":                       ["Linux", "Python"],
    "openjdk":                      ["Linux", "Java"],
    "eclipse-temurin":              ["Linux", "Java"],
    "golang":                       ["Linux", "Golang"],
    "nginx":                        ["Linux", "WebServer"],
    "httpd":                        ["Linux", "WebServer"],
    "mysql":                        ["Linux", "DatabaseServer", "MySQL"],
    "postgres":                     ["Linux", "DatabaseServer", "PostgreSQL"],
    "redis":                        ["Linux", "DatabaseServer", "Redis"],
    "mongo":                        ["Linux", "DatabaseServer", "MongoDB"],
    "elasticsearch":                ["Linux", "DatabaseServer", "Elasticsearch"],
    "rabbitmq":                     ["Linux", "WorkerNode"],
    "kafka":                        ["Linux", "WorkerNode"],
    "keycloak":                     ["Linux", "AuthServer"],
    "mcr.microsoft.com/dotnet":     ["Windows"],
    "mcr.microsoft.com/windows":    ["Windows"],
    "mcr.microsoft.com/mssql":      ["Windows", "DatabaseServer", "MSSQLServer"],
    "grafana":                      ["Linux"],
    "prometheus":                   ["Linux"],
    "traefik":                      ["Linux", "WebServer"],
    "haproxy":                      ["Linux", "WebServer"],
}

# Service/directory name patterns → node-group type
SERVICE_TYPE_PATTERNS: List[Tuple[str, str]] = [
    (r"web|api|app|frontend|backend|server|gateway|proxy|edge",  "WebServer"),
    (r"db|database|postgres|mysql|mongo|redis|mssql|elastic",    "DatabaseServer"),
    (r"auth|identity|ldap|keycloak|sso|iam",                     "AuthServer"),
    (r"worker|celery|queue|rabbit|kafka|job|task",               "WorkerNode"),
    (r"cache|memcache|redis",                                     "DatabaseServer"),
    (r"file|storage|minio|s3|blob|nas",                          "FileServer"),
    (r"dc|domain|ad|directory|controller",                        "DomainController"),
    (r"monitor|grafana|prometheus|kibana|logging",                "Linux"),
    (r"workstation|desktop|client|laptop|pc\b",                   "Workstation"),
]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class HelmChart:
    """One Bitnami/Helm chart with its app version and image references."""
    name:        str
    app_version: str                      # from Chart.yaml appVersion
    chart_version: str                    # from Chart.yaml version
    images:      List[str]               = field(default_factory=list)   # image:tag strings
    properties:  Set[str]               = field(default_factory=set)
    service_type: str                    = "Workstation"


@dataclass
class SubProject:
    """One package-manifest file and the service it represents."""
    path:         Path
    pkg_manager:  str
    packages:     List[str]   = field(default_factory=list)
    properties:   Set[str]    = field(default_factory=set)
    service_type: str         = "Workstation"


@dataclass
class DockerService:
    """One service entry from a docker-compose file."""
    name:       str
    image:      str
    ports:      List[str]  = field(default_factory=list)
    properties: Set[str]   = field(default_factory=set)


@dataclass
class RepoAnalysis:
    repo_dir:        Path
    subprojects:     List[SubProject]    = field(default_factory=list)
    docker_services: List[DockerService] = field(default_factory=list)
    helm_charts:     List[HelmChart]     = field(default_factory=list)
    all_properties:  Set[str]            = field(default_factory=set)
    service_map:     Dict[str, Set[str]] = field(default_factory=dict)
    # inferred network tiers: {tier_name: [service_names]}
    tiers:           Dict[str, List[str]] = field(default_factory=dict)


# ── Main analyser class ───────────────────────────────────────────────────────

class RepoAnalyzer:
    """Analyse a cloned repo directory and return a RepoAnalysis."""

    # ── public API ────────────────────────────────────────────────────────────

    def analyze(self, repo_dir: Path) -> RepoAnalysis:
        ra = RepoAnalysis(repo_dir=repo_dir)
        self._find_subprojects(ra)
        self._find_docker_services(ra)
        self._find_helm_charts(ra)
        self._aggregate(ra)
        self._infer_tiers(ra)
        return ra

    # ── subproject discovery ──────────────────────────────────────────────────

    _MANIFESTS: Dict[str, List[str]] = {
        "npm":    ["package.json"],
        "python": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"],
        "java":   ["pom.xml", "build.gradle", "build.gradle.kts"],
        "dotnet": ["*.csproj", "*.fsproj", "packages.config"],
        "ruby":   ["Gemfile"],
        "go":     ["go.mod"],
        "rust":   ["Cargo.toml"],
        "php":    ["composer.json"],
    }

    _SKIP_DIRS = frozenset({
        "node_modules", ".git", "vendor", "__pycache__",
        "dist", "build", ".tox", "venv", ".venv", "target",
    })

    def _find_subprojects(self, ra: RepoAnalysis):
        seen: Set[Path] = set()
        for pkg_mgr, patterns in self._MANIFESTS.items():
            for pattern in patterns:
                for mf in sorted(ra.repo_dir.rglob(pattern)):
                    if any(s in mf.parts for s in self._SKIP_DIRS):
                        continue
                    d = mf.parent
                    if d in seen:
                        continue
                    seen.add(d)
                    sp = SubProject(path=d, pkg_manager=pkg_mgr)
                    sp.packages     = extract_packages(mf, pkg_mgr)
                    sp.properties   = packages_to_props(sp.packages)
                    sp.service_type = infer_service_type(d.name, sp.properties)
                    ra.subprojects.append(sp)

    # ── docker-compose discovery ──────────────────────────────────────────────

    def _find_docker_services(self, ra: RepoAnalysis):
        for compose_file in ra.repo_dir.rglob("docker-compose*.yml"):
            if any(s in compose_file.parts for s in self._SKIP_DIRS):
                continue
            try:
                import yaml as _yaml
                doc = _yaml.safe_load(compose_file.read_text(errors="replace"))
                if not isinstance(doc, dict):
                    continue
                for svc_name, svc_cfg in (doc.get("services") or {}).items():
                    if not isinstance(svc_cfg, dict):
                        continue
                    image = svc_cfg.get("image") or ""
                    ports = [str(p) for p in (svc_cfg.get("ports") or [])]
                    ds = DockerService(name=svc_name, image=image, ports=ports)
                    ds.properties = image_to_props(image) | service_name_to_props(svc_name)
                    ra.docker_services.append(ds)
            except Exception:
                pass

    # ── Helm chart discovery ──────────────────────────────────────────────────

    def _find_helm_charts(self, ra: RepoAnalysis):
        """Parse Chart.yaml + values.yaml for every Helm chart found in the repo."""
        import yaml as _yaml

        for chart_yaml in sorted(ra.repo_dir.rglob("Chart.yaml")):
            if any(s in chart_yaml.parts for s in self._SKIP_DIRS):
                continue
            try:
                meta = _yaml.safe_load(chart_yaml.read_text(errors="replace")) or {}
            except Exception:
                continue

            name          = meta.get("name", chart_yaml.parent.name)
            app_version   = str(meta.get("appVersion", "")).strip('"')
            chart_version = str(meta.get("version", "")).strip('"')

            # Extract image refs from values.yaml
            images: List[str] = []
            values_file = chart_yaml.parent / "values.yaml"
            if values_file.exists():
                try:
                    vals = _yaml.safe_load(values_file.read_text(errors="replace")) or {}
                    images = _extract_images_from_values(vals)
                except Exception:
                    pass

            # Derive properties from chart name + images
            props  = service_name_to_props(name) | _chart_name_to_props(name)
            for img in images:
                props |= image_to_props(img.split(":")[0])

            hc = HelmChart(
                name          = name,
                app_version   = app_version,
                chart_version = chart_version,
                images        = images,
                properties    = props,
                service_type  = infer_service_type(name, props),
            )
            ra.helm_charts.append(hc)

    # ── aggregation ───────────────────────────────────────────────────────────

    def _aggregate(self, ra: RepoAnalysis):
        all_props: Set[str] = set()
        svc_map: Dict[str, Set[str]] = {}

        for sp in ra.subprojects:
            props = sp.properties | ({sp.service_type} if sp.service_type else set())
            all_props |= props
            key = sp.path.relative_to(ra.repo_dir).parts[0] if sp.path != ra.repo_dir else sp.path.name
            svc_map.setdefault(str(key), set()).update(props)

        for ds in ra.docker_services:
            all_props |= ds.properties
            svc_map.setdefault(ds.name, set()).update(ds.properties)

        for hc in ra.helm_charts:
            props = hc.properties | ({hc.service_type} if hc.service_type else set())
            all_props |= props
            svc_map.setdefault(hc.name, set()).update(props)

        ra.all_properties = all_props
        ra.service_map    = svc_map

    def _infer_tiers(self, ra: RepoAnalysis):
        """Group services into network tiers by type."""
        tiers: Dict[str, List[str]] = {
            "WebTier":      [],
            "AppTier":      [],
            "DataTier":     [],
            "AuthTier":     [],
            "WorkerTier":   [],
        }
        for svc, props in ra.service_map.items():
            if "DomainController" in props or "AuthServer" in props:
                tiers["AuthTier"].append(svc)
            elif "DatabaseServer" in props:
                tiers["DataTier"].append(svc)
            elif "WorkerNode" in props:
                tiers["WorkerTier"].append(svc)
            elif "WebServer" in props:
                tiers["WebTier"].append(svc)
            else:
                tiers["AppTier"].append(svc)

        ra.tiers = {k: v for k, v in tiers.items() if v}


# ── Helm-specific helpers ─────────────────────────────────────────────────────

# Chart name patterns that map to well-known properties
_CHART_PROP_MAP: List[Tuple[str, List[str]]] = [
    (r"postgresql|postgres",           ["DatabaseServer", "PostgreSQL", "Linux"]),
    (r"mysql|mariadb",                 ["DatabaseServer", "MySQL", "Linux"]),
    (r"mongodb|mongo",                 ["DatabaseServer", "MongoDB", "Linux"]),
    (r"redis",                         ["DatabaseServer", "Redis", "Linux"]),
    (r"elasticsearch|opensearch",      ["DatabaseServer", "Elasticsearch", "Linux"]),
    (r"cassandra",                     ["DatabaseServer", "Linux"]),
    (r"kafka|zookeeper",               ["WorkerNode", "Linux"]),
    (r"rabbitmq",                      ["WorkerNode", "Linux"]),
    (r"nginx|apache|httpd",            ["WebServer", "Linux"]),
    (r"wordpress|drupal|joomla",       ["WebServer", "PHP", "Linux"]),
    (r"grafana|kibana",                ["Linux"]),
    (r"prometheus",                    ["Linux"]),
    (r"jenkins|gitlab|gitea|harbor",   ["Linux"]),
    (r"keycloak|oauth|dex\b",          ["AuthServer", "Linux"]),
    (r"minio",                         ["FileServer", "Linux"]),
    (r"etcd",                          ["Linux"]),
    (r"vault",                         ["Linux"]),
    (r"airflow|spark|flink",           ["WorkerNode", "Linux"]),
    (r"jupyter|mlflow",                ["Linux"]),
    (r"aspnet|dotnet",                 ["WebServer", "Windows"]),
    (r"mssql|sqlserver",               ["DatabaseServer", "MSSQLServer", "Windows"]),
    (r"activedirectory|openldap|freeipa", ["DomainController", "Linux"]),
]


def _chart_name_to_props(chart_name: str) -> Set[str]:
    """Map a Helm chart name to CyberBattleSim properties."""
    props: Set[str] = set()
    for pattern, prop_list in _CHART_PROP_MAP:
        if re.search(pattern, chart_name, re.I):
            props.update(prop_list)
    return props


def _extract_images_from_values(vals: dict, _depth: int = 0) -> List[str]:
    """Recursively extract image:tag strings from a Helm values dict."""
    if _depth > 6:
        return []
    images: List[str] = []
    if not isinstance(vals, dict):
        return images
    repo = vals.get("repository", "")
    tag  = vals.get("tag", "")
    reg  = vals.get("registry", "")
    if repo and isinstance(repo, str):
        full = f"{reg}/{repo}:{tag}" if reg else f"{repo}:{tag}"
        images.append(full.strip(":"))
    for v in vals.values():
        if isinstance(v, dict):
            images.extend(_extract_images_from_values(v, _depth + 1))
    return images


# ── Package-level helpers ─────────────────────────────────────────────────────

def extract_packages(manifest: Path, pkg_mgr: str) -> List[str]:
    """Parse a manifest file and return a flat list of package names."""
    text = manifest.read_text(errors="replace")
    pkgs: List[str] = []

    if pkg_mgr == "npm":
        try:
            doc = json.loads(text)
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                pkgs.extend(doc.get(section, {}).keys())
        except Exception:
            pass

    elif pkg_mgr == "python":
        for line in text.splitlines():
            line = re.sub(r"[>=<!#\[\s].*", "", line).strip()
            if line and not line.startswith(("-", ".")):
                pkgs.append(line.lower())

    elif pkg_mgr == "java":
        pkgs.extend(re.findall(r"<artifactId>([^<]+)</artifactId>", text))
        pkgs.extend(re.findall(r"['\"]([a-zA-Z][\w.\-]+:[\w.\-]+)['\"]", text))

    elif pkg_mgr == "dotnet":
        pkgs.extend(re.findall(r'Include="([^"]+)"', text, re.I))

    elif pkg_mgr in ("ruby", "php"):
        pkgs.extend(re.findall(r"""(?:gem|require)\s+['"]([^'"]+)['"]""", text))

    elif pkg_mgr == "go":
        pkgs.extend(re.findall(r"^\s+([\w./\-]+)\s+v", text, re.MULTILINE))

    elif pkg_mgr == "rust":
        pkgs.extend(re.findall(r'^([\w\-]+)\s*=', text, re.MULTILINE))

    return [p.lower().strip() for p in pkgs if p.strip()]


def packages_to_props(packages: List[str]) -> Set[str]:
    """Map package names to CyberBattleSim property names."""
    props: Set[str] = set()
    for pkg in packages:
        for pattern, prop_list in PKG_TO_PROPS:
            if re.search(pattern, pkg, re.I):
                props.update(prop_list)
    return props


def image_to_props(image: str) -> Set[str]:
    """Map a Docker image name to CyberBattleSim properties."""
    props: Set[str] = set()
    base = image.lower().split(":")[0]
    for key, prop_list in IMAGE_TO_PROPS.items():
        if key in base:
            props.update(prop_list)
    return props or {"Linux"}


def service_name_to_props(name: str) -> Set[str]:
    """Infer properties from a service/directory name."""
    props: Set[str] = set()
    for pattern, prop in SERVICE_TYPE_PATTERNS:
        if re.search(pattern, name, re.I):
            props.add(prop)
    return props


def infer_service_type(dirname: str, existing_props: Set[str]) -> str:
    """Pick the most specific service type for a directory."""
    for pattern, stype in SERVICE_TYPE_PATTERNS:
        if re.search(pattern, dirname, re.I):
            return stype
    for candidate in ("WebServer", "DatabaseServer", "FileServer",
                       "AuthServer", "DomainController", "WorkerNode"):
        if candidate in existing_props:
            return candidate
    return "Workstation"


# ── Serialisation ─────────────────────────────────────────────────────────────

def repo_analysis_to_dict(ra: RepoAnalysis) -> dict:
    return {
        "repo_dir": str(ra.repo_dir),
        "subprojects": [
            {
                "path":         str(sp.path.relative_to(ra.repo_dir)),
                "pkg_manager":  sp.pkg_manager,
                "packages":     sp.packages[:40],
                "properties":   sorted(sp.properties),
                "service_type": sp.service_type,
            }
            for sp in ra.subprojects
        ],
        "docker_services": [
            {
                "name":       ds.name,
                "image":      ds.image,
                "ports":      ds.ports,
                "properties": sorted(ds.properties),
            }
            for ds in ra.docker_services
        ],
        "helm_charts": [
            {
                "name":          hc.name,
                "app_version":   hc.app_version,
                "chart_version": hc.chart_version,
                "images":        hc.images[:5],
                "properties":    sorted(hc.properties),
                "service_type":  hc.service_type,
            }
            for hc in ra.helm_charts
        ],
        "all_properties":  sorted(ra.all_properties),
        "service_map":     {k: sorted(v) for k, v in ra.service_map.items()},
        "tiers":           {k: v for k, v in ra.tiers.items()},
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyse a cloned repo for CyberBattleSim properties")
    parser.add_argument("--repo", required=True, help="Path to cloned repo directory")
    parser.add_argument("--out",  default="",   help="Save JSON to file (default: stdout)")
    args = parser.parse_args()

    analyzer = RepoAnalyzer()
    analysis = analyzer.analyze(Path(args.repo))
    data     = repo_analysis_to_dict(analysis)

    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=2))
        print(f"Saved to {args.out}")
    else:
        print(json.dumps(data, indent=2))
