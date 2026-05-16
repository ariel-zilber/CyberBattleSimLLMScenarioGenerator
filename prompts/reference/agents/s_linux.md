# Agent 2: S_Linux — Cloud & Container Specialist

**Zones:** Z6 AWS Cloud (WebTier → AppTier → WorkerTier → DataTier)  
**CVE source:** `bitnami_cves.json`  
**Terminal goal (standalone):** `AWSRedis` (value 10000, is_goal: true)  
**Terminal goal (meta/integrated):** `AWSPostgreSQL` (value 10000, is_goal: true)

---

## Action Types

| CBS Action Category | type | Allowed? | Rationale |
|--------------------|------|----------|-----------|
| `probe` vulnerabilities | REMOTE | ✅ Yes | Linux distro fingerprinting before library CVE selection |
| `remote_access` solvability | REMOTE | ✅ Yes | Bitnami library CVEs — network-reachable RCEs |
| `remote_access` solvability | LOCAL | ✅ Yes | Container escape from within an owned container |
| `credential_leak` solvability | LOCAL | ✅ Yes | wp-config.php, env vars, Docker socket (requires node ownership) |
| `discovery` solvability | — | ❌ No | S_Recon |
| `goal_access` solvability | — | ❌ No | Goal nodes reached via S_Recon credential chain |
| `KNOWS` constraint | — | ❌ No | S_Recon |
| `LEAK_KNOWN_CREDENTIALS` constraint | — | ❌ No | S_Recon |

---

## Vulnerabilities

### Probe Vulnerabilities (type: REMOTE, SR 1.0)
| Name | OS Target |
|------|-----------|
| `Remote.Probe.Linux` | Linux (any distro) |
| `Remote.Probe.Alpine` | Alpine Linux |
| `Remote.Probe.Debian` | Debian / Ubuntu |

### Remote Access Vulnerabilities (type: REMOTE — network-reachable)
| Name | CVE | CVSS | SR | Service | Library / Attack |
|------|-----|------|----|---------|-----------------|
| `Solvability.Concourse_ContainerEscape` | CVE-2020-5415 | 10.0 | 0.90 | AWSWorkerNode | Concourse pre-6.3.1 container escape |
| `Solvability.ApacheSpark_PrivEsc` | CVE-2023-22946 | 9.9 | 0.90 | AWSWorkerNode | Spark config proxy privilege escalation |
| `Solvability.SnakeYAML_Deserialization` | CVE-2022-1471 | 9.8 | 0.90 | AWSAppServer | Java deserialization via SnakeYAML Constructor |
| `Solvability.ImageMagick_ShellInject` | CVE-2025-53014 | 9.8 | 0.90 | AWSWebServer | ImageMagick shell command injection |
| `Solvability.MySQL2_SQLInject_1` | CVE-2024-21508 | 9.8 | 0.90 | AWSMySQL | mysql2 <3.9.4 SQL injection / RCE |
| `Solvability.MySQL2_SQLInject_2` | CVE-2024-21511 | 9.8 | 0.90 | AWSMySQL | mysql2 <3.9.7 SQL injection variant |
| `Solvability.JavaDeserialize_RCE_1` | CVE-2024-55637 | 9.8 | 0.90 | AWSAppServer | Java deserialization untrusted data |
| `Solvability.JavaDeserialize_RCE_2` | CVE-2024-55638 | 9.8 | 0.90 | AWSAppServer | Java deserialization untrusted data variant |
| `Solvability.GhostCMS_CSV_Injection` | CVE-2024-34448 | 8.8 | 0.88 | AWSWebServer | Ghost CMS CSV injection → RCE |
| `Solvability.ApacheAvro_Deserialization` | CVE-2024-47561 | 8.8 | 0.88 | AWSWorkerNode | Apache Avro schema deserialization RCE |
| `Solvability.LibSSH_OpenSSL_RCE` | CVE-2025-5372 | 8.8 | 0.88 | AWSAppServer | libssh built with OpenSSL RCE |
| `Solvability.GoGoProtobuf_Deserialization` | CVE-2021-3121 | 8.6 | 0.86 | AWSWorkerNode | GoGo Protobuf deserialization OOB write |
| `Solvability.Zlib_IntOverflow` | CVE-2023-45853 | 9.8 | 0.90 | AWSAppServer | MiniZip integer overflow → heap OOB write |
| `Solvability.OpenEXR_OOB_Write` | CVE-2023-5841 | 9.1 | 0.90 | AWSAppServer | OpenEXR scanline count OOB write |
| `Solvability.PgDump_UntrustedData` | CVE-2025-8714 | 8.8 | 0.88 | AWSPostgreSQL | pg_dump untrusted data inclusion → RCE |
| `Solvability.PgDump_Newline_Injection` | CVE-2025-8715 | 8.8 | 0.88 | AWSPostgreSQL | pg_dump newline injection |
| `Solvability.ApacheCommons_AccessControl` | CVE-2025-48734 | 8.8 | 0.88 | AWSAppServer | Apache Commons improper access control |
| `Solvability.Elasticsearch_Groovy_RCE` | CVE-2015-1427 | 9.8 | 0.90 | AWSElasticsearch | Groovy sandbox escape → unauthenticated RCE |
| `Solvability.NodeJS_IP_SSRF` | CVE-2024-29415 | 9.8 | 0.90 | AWSAppServer | Node.js ip package SSRF → internal access |
| `Solvability.Git_PathTraversal` | CVE-2025-48385 | 8.3 | 0.83 | AWSGitLab | Git path traversal → arbitrary file write |
| `Solvability.GoCrypto_SSH_AuthBypass` | CVE-2024-45337 | 8.2 | 0.57 | AWSAppServer | Go crypto/ssh misuse → auth bypass |
| `Solvability.SQLite3_IntOverflow` | CVE-2025-7458 | 9.1 | 0.90 | AWSAppServer | SQLite3 integer overflow in key info |
| `Solvability.LibXML2_UseAfterFree_1` | CVE-2025-49794 | 9.1 | 0.90 | AWSWebServer | libxml2 use-after-free in processing |
| `Solvability.LibXML2_UseAfterFree_2` | CVE-2025-49796 | 9.1 | 0.90 | AWSWebServer | libxml2 vulnerability in complex content |

### Local Access Vulnerabilities (type: LOCAL — require owning the container first)
| Name | SR | Service | Attack |
|------|----|---------|--------|
| `Solvability.Docker_Socket_Escape` | 0.85 | AWSAppServer | Mounted Docker socket → host root via API |
| `Solvability.Kubernetes_HostPID_Escape` | 0.80 | AWSWorkerNode | hostPID=true pod → nsenter host process |
| `Solvability.Container_ProcMount_Escape` | 0.75 | AWSWorkerNode | Unmasked /proc/sysrq-trigger → host exec |
| `Solvability.Redis_Noauth_Config_Rewrite` | 0.85 | AWSRedis | CONFIG SET slaveof on unauthenticated Redis → RCE |
| `Solvability.Hadoop_FileUtil_Inject` | CVE-2022-25168 | 0.88 | AWSWorkerNode | FileUtil.unTar path injection → arbitrary write |
| `Solvability.Bundler_DNSHijack` | CVE-2020-36327 | 0.88 | AWSAppServer | Bundler DNS hijack → malicious gem install |

### Credential Leak Vulnerabilities (type: LOCAL — from owned container)

> **Boundary rule:** S_Linux *extracts* credentials (puts them in the CBS credential store). S_Recon *propagates* them across node boundaries via `LEAK_KNOWN_CREDENTIALS`. Both steps must execute for a cross-node credential chain to complete. `Solvability.AWS_CredFile` here (extraction) and `Solvability.Cloud_CredFile` in S_Recon (propagation to AWSPostgreSQL) are distinct CBS actions, not duplicates.

| Name | SR | Source Node | Leaked Credential |
|------|----|------------|-------------------|
| `Solvability.WordPressDB_Creds` | 0.72 | AWSWebServer | MySQL / PostgreSQL password |
| `Solvability.Container_EnvVars` | 0.75 | AWSAppServer, AWSWorkerNode | All container env vars (API keys, DB passwords) |
| `Solvability.AWS_CredFile` | 0.75 | AWSAppServer | `~/.aws/credentials` → IAM access key |
| `Solvability.VaultToken_EnvVar` | 0.68 | AWSAppServer | HashiCorp Vault root token |
| `Solvability.KubeServiceAccount` | 0.78 | AWSWorkerNode | Mounted K8s service account JWT |

---

## Services and Ports

| Service | Primary Ports | Protocol | Container Runtime | Z6 Tier |
|---------|--------------|----------|------------------|---------|
| `AWSWebServer` | 80, 443 | HTTP, HTTPS | Nginx / WordPress / Apache | WebTier |
| `AWSAppServer` | 3000, 8080, 8200 | HTTP, HTTPS | Node.js / Go / Vault | AppTier |
| `AWSRedis` | 6379 | Redis binary | Redis (GoRuntime) | DataTier Hub |
| `AWSPostgreSQL` | 5432 | PostgreSQL | PostgreSQL / Alpine | DataTier |
| `AWSMySQL` | 3306 | MySQL | MySQL / Debian | DataTier |
| `AWSElasticsearch` | 9200, 9300 | HTTP, binary | Elasticsearch / Java | DataTier |
| `AWSCassandra` | 9042 | CQL | Cassandra / Java | DataTier |
| `AWSWorkerNode` | 9092, 2181 | Kafka, Zookeeper | Kafka / Java | WorkerTier |
| `AWSRabbitMQ` | 5672, 15672 | AMQP, HTTP | RabbitMQ | WorkerTier |
| `AWSAuthServer` | 8080, 8443 | HTTP, HTTPS | Keycloak / Java | AuthTier |
| `AWSGitLab` | 80, 443, 22 | HTTP, HTTPS, SSH | GitLab | MgmtTier |
| `AWSJenkins` | 8080 | HTTP | Jenkins | MgmtTier |

---

## Goal Specification

```yaml
# ── Standalone specialist training ──────────────────────────────────────────
goal_config:
  num_goals: 1
  selection_strategy: diverse

AWSWebServer:  value: 1000   is_goal: false   # Entry tier
AWSAppServer:  value: 3500   is_goal: false   # Mid tier
AWSRedis:      value: 10000  is_goal: true    # TERMINAL GOAL (standalone)
```

**Standalone note:** AWSRedis is the terminal goal for isolated S_Linux training because it is reachable without cross-node credential propagation: AWSWebServer (REMOTE exploit) → AWSAppServer (REMOTE exploit) → AWSRedis (LOCAL: `Redis_Noauth_Config_Rewrite`). AWSPostgreSQL cannot be the standalone goal — it has no REMOTE CVEs and S_Linux does not hold `LEAK_KNOWN_CREDENTIALS`, so the episode would never terminate.

```yaml
# ── Meta / integrated training ───────────────────────────────────────────────
AWSWebServer:   value: 1000   is_goal: false   # Entry tier
AWSAppServer:   value: 3500   is_goal: false   # Mid tier
AWSRedis:       value: 6500   is_goal: false   # Near-goal (hub shortcut reward)
AWSPostgreSQL:  value: 10000  is_goal: true    # TERMINAL GOAL
```

**Meta note:** AWSPostgreSQL has no REMOTE CVEs (Alpine, no exposed attack surface). Goal is only reachable via S_Recon `LEAK_KNOWN_CREDENTIALS` propagation from wp-config or Redis credentials. This is intentional — forces the credential chain.
