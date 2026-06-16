# Allowed Properties Dictionary

This document provides an exhaustive reference of every valid string that can appear in `identifiers.base_properties`, `services.default_properties`, `solvability_vulnerabilities.match_properties`, and `constraints.target` (for `MUST_HAVE` rules).

**Important:** You must include EVERY property you use in your YAML in the `identifiers.base_properties` list. The parser will reject any property referenced but not declared.

---

## 1. Required System Properties

These must always be present in `base_properties`:

| Property | Description |
|----------|-------------|
| `breach_node` | **Mandatory.** Marks the attacker's start node. Every `identifiers.base_properties` list MUST contain this. |

---

## 2. Operating System Properties

### 2.1 OS Families (use in `allowed_os` and `default_properties`)

| Property | Description |
|----------|-------------|
| `Windows` | Generic Windows OS family |
| `Linux` | Generic Linux OS family |
| `MacOS` | Apple macOS (rare in enterprise servers) |
| `Unix` | Generic Unix (for legacy systems) |

### 2.2 Windows Versions

| Property | Description | Notes |
|----------|-------------|-------|
| `WinXP` | Windows XP | Extremely legacy workstation |
| `Win7` | Windows 7 | Legacy; EternalBlue-vulnerable |
| `Win8` | Windows 8 / 8.1 | Uncommon in enterprise |
| `Win10` | Windows 10 | Modern endpoint |
| `Win11` | Windows 11 | Newest endpoint |
| `Win2003` | Windows Server 2003 | Extremely legacy |
| `Win2008` | Windows Server 2008 / R2 | Legacy server |
| `Win2012` | Windows Server 2012 / R2 | Older server |
| `Win2016` | Windows Server 2016 | Common enterprise server |
| `Win2019` | Windows Server 2019 | Common enterprise server |
| `Win2022` | Windows Server 2022 | Latest server OS |

### 2.3 Linux Distributions

| Property | Description |
|----------|-------------|
| `Ubuntu` | Ubuntu Linux |
| `CentOS` | CentOS / RHEL-based |
| `Debian` | Debian Linux |
| `Alpine` | Alpine Linux (containers) |
| `Kali` | Kali Linux (pentesting) |
| `RedHat` | Red Hat Enterprise Linux |

---

## 3. Node Role / Type Properties

### 3.1 Endpoint Roles

| Property | Description |
|----------|-------------|
| `Workstation` | Generic workstation |
| `LegacyWorkstation` | Older, less patched workstation |
| `ModernWorkstation` | Up-to-date workstation |
| `LaptopUser` | Mobile endpoint |
| `DeveloperWorkstation` | Developer machine with elevated privileges |
| `AdminWorkstation` | Administrator/privileged workstation with elevated domain rights |

### 3.2 Server Roles

| Property | Description |
|----------|-------------|
| `WebServer` | Generic web server |
| `NginxServer` | Nginx web server |
| `ApacheServer` | Apache HTTP server |
| `IISServer` | Microsoft IIS web server |
| `LoadBalancer` | Load balancer / traffic distributor |
| `ReverseProxy` | Reverse proxy |
| `FileServer` | Windows SMB file server |
| `PrintServer` | Windows print server |
| `MailServer` | Email server |
| `FTPServer` | FTP server |
| `AppServer` | Application server |
| `HyperVHost` | Windows Hyper-V hypervisor host | Required for HyperV_RCE |
| `MSMQServer` | Microsoft Message Queuing server | Required for QueueJumper, MSMQ_RCE_* |
| `APIGateway` | API gateway |
| `Middleware` | Application middleware |
| `CacheServer` | Redis/Memcached cache server |
| `MessageBroker` | RabbitMQ/Kafka message broker |
| `BackupServer` | Backup server |

### 3.3 Database Servers

| Property | Description |
|----------|-------------|
| `DatabaseServer` | Generic database server |
| `MSSQLServer` | Microsoft SQL Server |
| `MySQLServer` | MySQL database server |
| `PostgreSQLServer` | PostgreSQL database server |
| `MongoDBServer` | MongoDB NoSQL server |
| `RedisServer` | Redis in-memory store |
| `ElasticsearchServer` | Elasticsearch server |
| `OracleServer` | Oracle Database server |
| `PostgreSQL` | PostgreSQL database (port/protocol) |
| `NoSQL`      | Generic NoSQL database              |

### 3.4 Active Directory / Identity

| Property | Description |
|----------|-------------|
| `DomainController` | Active Directory Domain Controller |
| `ADCS` | Active Directory Certificate Services |
| `ADFS` | Active Directory Federation Services |
| `LDAPServer` | LDAP directory server |
| `RadiusServer` | RADIUS authentication server |
| `IdentityProvider` | OAuth/SAML identity provider |
| `ADAppServer`          | AD-integrated application server |
| `ADConnector`          | AD connector/sync service        |
| `ADFileServer`         | AD-integrated file server        |
| `ADIntegrated`         | AD-integrated application        |
| `ADReplication`        | AD replication partner           |
| `ADSQLServer`          | AD-integrated SQL server         |
| `ADVPNServer`          | AD-integrated VPN server         |
| `AD_CS`                | AD Certificate Services          |
| `CertAuthority`        | Certificate Authority server     |
| `CertificateAuthority` | Generic PKI CA                   |

### 3.5 Cloud & Container Infrastructure

| Property | Description |
|----------|-------------|
| `Kubernetes` | Kubernetes cluster node |
| `Pod` | Kubernetes pod |
| `Container` | Generic container |
| `etcd` | Kubernetes etcd key-value store |
| `Kubelet` | Kubernetes kubelet agent |
| `ControlPlane` | Kubernetes control plane |
| `WorkerNode` | Kubernetes worker node |
| `APIServer` | Kubernetes API server |
| `CloudInstance` | Generic cloud VM |
| `S3Bucket` | AWS S3 / object storage |
| `IAMRole` | Cloud IAM role |
| `AWS`             | AWS cloud environment        |
| `Cloud`           | Generic cloud infrastructure |
| `CloudAPIGateway` | Cloud API gateway            |
| `CloudEC2`        | AWS EC2 instance             |
| `CloudFront`      | AWS CloudFront CDN           |
| `CloudFrontDist`  | CloudFront distribution      |
| `CloudLambda`     | AWS Lambda function          |
| `CloudRDS`        | AWS RDS database             |
| `CloudS3`         | AWS S3 bucket                |
| `CloudWatch`      | AWS CloudWatch service       |
| `CloudWatchLogs`  | CloudWatch Logs service      |
| `DynamoDB`        | AWS DynamoDB table           |
| `DynamoDBTable`   | DynamoDB table resource      |
| `EC2`             | EC2 instance                 |
| `EKS`             | AWS EKS Kubernetes cluster   |
| `ECS`             | AWS ECS container service    |
| `ECSContainer`    | ECS container instance       |
| `ElastiCache`     | AWS ElastiCache              |
| `ElastiCacheNode` | ElastiCache node             |
| `IMDS`            | Instance Metadata Service    |
| `IMDSv1`          | IMDSv1 (vulnerable)          |
| `IMDSv2`          | IMDSv2 (secure)              |
| `K8sCluster`      | Kubernetes cluster           |
| `Lambda`          | Serverless Lambda function   |
| `S3`              | AWS S3 service               |
| `S3Bucket`        | S3 bucket resource           |
| `Serverless`      | Serverless compute           |

### 3.7 Network / Security Infrastructure
| Property     | Description                 |
| ------------ | --------------------------- |
| `Bastion`      | Bastion/jump host           |
| `BastionHost`  | SSH jump server             |
| `DMZ`          | DMZ zone placement          |
| `Firewall`     | Network firewall            |
| `ForwardProxy` | Forward proxy server        |
| `NAT`          | Network Address Translation |
| `VPN`          | VPN endpoint                |
| `VPNEndpoint`  | VPN termination point       |
| `VPNGateway`   | VPN gateway                 |
| `WAF`          | Web Application Firewall    |
| `WAFAppliance` | WAF hardware appliance      |
| `WAFNode`      | WAF cluster node            |

### 3.7b Network Device & Vendor Properties

These properties are derived from `data/vulnerability_db/network_devices_cves.json`
(240 CVEs — Cisco, Juniper, Fortinet, Palo Alto, F5, Citrix, Mikrotik, …).

#### Generic roles

| Property | Description |
|----------|-------------|
| `NetworkDevice` | Generic network infrastructure device |
| `Router` | Layer-3 router |
| `Switch` | Layer-2/3 switch |
| `NGFW` | Next-generation firewall |
| `NetworkManagement` | Network management station (NMS/NMS) |
| `JumpServer` | Network jump/bastion server |
| `RemoteAccess` | Remote access server (VPN/RAS) |
| `AAA` | Authentication, Authorization, Accounting server |
| `SSLVPN` | SSL VPN gateway |

#### Cisco

| Property | Description |
|----------|-------------|
| `CiscoIOS` | Cisco IOS / IOS-XE router |
| `CiscoNXOS` | Cisco NX-OS switch/data-center fabric |
| `CiscoASA` | Cisco ASA firewall |
| `CiscoFirepower` | Cisco Firepower / FTD NGFW |
| `CiscoSD_WAN` | Cisco SD-WAN (Viptela) |
| `BGP` | BGP routing enabled |
| `OSPF` | OSPF routing enabled |
| `STP` | Spanning Tree Protocol |
| `VLAN` | VLAN-segmented switch |
| `RADIUS` | RADIUS AAA client |
| `Telnet` | Telnet management enabled (legacy) |
| `SNMP` | SNMP v1/v2c enabled |
| `CDP` | Cisco Discovery Protocol enabled |

#### Juniper

| Property | Description |
|----------|-------------|
| `JuniperJunos` | Juniper Networks Junos OS device |

#### Fortinet

| Property | Description |
|----------|-------------|
| `FortiGate` | Fortinet FortiGate firewall/UTM |
| `FortiOS` | Fortinet FortiOS firmware |

#### Palo Alto Networks

| Property | Description |
|----------|-------------|
| `PaloAlto` | Palo Alto Networks device |
| `PANOS` | Palo Alto PAN-OS firmware |
| `GlobalProtect` | Palo Alto GlobalProtect VPN |

#### F5 / Citrix

| Property | Description |
|----------|-------------|
| `F5BIGIP` | F5 BIG-IP application delivery controller |
| `CitrixADC` | Citrix ADC (formerly NetScaler) |
| `Netscaler` | NetScaler / Citrix ADC |

#### Other vendors

| Property | Description |
|----------|-------------|
| `SonicWall` | SonicWall firewall |
| `CheckPoint` | Check Point firewall/gateway |
| `Mikrotik` | Mikrotik RouterOS |
| `OpenWrt` | OpenWrt firmware |
| `Netgear` | Netgear router/switch |
| `DLink` | D-Link router/access point |
| `Zyxel` | Zyxel firewall/router |

#### Security posture (network-specific)

| Property | Description |
|----------|-------------|
| `DefaultCredentials` | Device still uses factory default credentials |
| `LegacyDevice` | End-of-life / unsupported network device |

---

## 4. Security Posture Properties

### 4.1 Patch & Configuration State

| Property | Description | Use case |
|----------|-------------|----------|
| `Unpatched` | Missing critical patches | Required for EternalBlue, BlueKeep, LibCrypto CVEs |
| `Patched` | Up-to-date patch level | Explicitly marks modern nodes |
| `Legacy` | Outdated software stack | General legacy marker |
| `Misconfigured` | Security misconfiguration present | General misconfiguration marker |

### 4.2 Windows Credential Hygiene

| Property | Description | Use case |
|----------|-------------|----------|
| `LAPS` | Local Admin Password Solution enabled | Prevents local admin reuse |
| `NoLAPS` | LAPS not installed | Required for lateral movement via local admin |
| `Kerberoastable` | Service account with SPN registered | Required for Kerberoasting exploits |
| `ASREProastable` | Account with pre-auth disabled | Required for AS-REP roasting |
| `DomainJoined` | Member of an Active Directory domain | Required for Kerberos/AD attacks |
| `DomainAdmin` | Has Domain Admin privileges | Required for DCSync |
| `LocalAdmin` | Has local administrator rights | For pass-the-hash attacks |
| `ServiceAccount` | Runs as a service account | Required for Kerberoasting |
| `UnconstrainedDelegation` | Kerberos unconstrained delegation enabled | Required for DelegationAbuse |
| `ZeroLogonVulnerable` | Unpatched CVE-2020-1472 Netlogon flaw | Required for ZeroLogon exploit |
| `NTLMRelayable` | NTLM authentication relayable (SMB signing disabled) | Required for NTLM relay attacks |

### 4.3 Protocol Vulnerabilities

| Property | Description | Use case |
|----------|-------------|----------|
| `SMBv1` | Legacy SMBv1 protocol enabled | Required for EternalBlue |
| `WDigest` | WDigest authentication enabled | Allows plaintext cred dump |
| `PrintSpooler` | Windows Print Spooler running | Required for PrintNightmare |
| `VNC_Enabled` | VNC remote desktop enabled | Lateral movement via VNC |
| `Telnet_Enabled` | Telnet service enabled | Legacy remote access |
| `AnonymousAuth` | Anonymous authentication allowed | Unauthenticated access |
| `NoAuth` | No authentication required | For legacy/misconfigured services |
| `VendorLocked` | Cannot be patched (vendor constraint) | For end-of-life network devices |
| `PrintSpooler` | Windows Print Spooler service running | PrintNightmare, SpoolSample |

### 4.4 Exploit-Specific Properties

| Property | Description |
|----------|-------------|
| `WebConfig` | Web application config files present (may contain creds) |
| `WebAppCredentials` | Web application credentials stored on node |
| `OpenSSL` | OpenSSL library present (Heartbleed risk) |
| `ShellShock` | Vulnerable to Bash Shellshock |

### 4.5 Cloud Security
| Property        | Description                | Use case           |
| --------------- | -------------------------- | ------------------ |
| `IAM`           | IAM roles/policies present | IAM enumeration    |
| `IAMRole`       | Assumed IAM role           | Role enumeration   |
| `PublicRead`    | Public read access         | S3 bucket exposure |
| `PublicSubnet`  | Public cloud subnet        | External exposure  |
| `CloudFederated` | Azure AD / ADFS Seamless SSO federated identity enabled on node | Required target property for `Solvability.CloudIAM_LDAP_Write` (Z6→Z1 cloud-to-corp crossing). Must appear on the Z1 DomainController that accepts the federated IAM token via AD Seamless SSO. |
---

## 5. Access & Authentication Properties

| Property | Description |
|----------|-------------|
| `Unauthenticated` | No authentication required — **DO NOT use on goal nodes** |
| `PrivilegedAccess` | Node has elevated system privileges |
| `HostPID` | Container shares host PID namespace |
| `HostNetwork` | Container shares host network namespace |
| `NonPrivileged` | Standard user-level access only |
| `AdminCredentials` | Administrator credentials stored on node |
| `SSHKey` | SSH private key present on node |

---

## 6. Data Classification Properties

| Property | Description |
|----------|-------------|
| `SensitiveData` | Generic sensitive data present |
| `CustomerData` | Customer personal data (PII) |
| `FinancialData` | Financial records |
| `PaymentCard` | Payment card data (PCI DSS scope) |
| `GDPR` | GDPR-regulated system |
| `PCI` | PCI DSS-regulated system |
| `HRData` | Human Resources data |
---

## 7. Network Protocol Properties

These can be used as properties to mark which protocols are active on a node.

| Property | Description |
|----------|-------------|
| `LDAP` | LDAP protocol active |
| `LDAPS` | Secure LDAP active |
| `Kerberos` | Kerberos authentication active |
| `HTTPS` | HTTPS service active |
| `HTTP` | HTTP service active |
| `SSH` | SSH service active |
| `RDP` | Remote Desktop Protocol active |
| `SMB` | SMB file sharing active |
| `MSSQL` | MSSQL database port active |
| `MySQL` | MySQL database port active |
| `PostgreSQL` | PostgreSQL port active |
| `Redis` | Redis port active |
| `gRPC` | gRPC remote procedure call |
| `AMQP` | AMQP messaging protocol |
| `FTP` | FTP file transfer |
| `GraphQL` | GraphQL API protocol |
| `RADIUS` | RADIUS authentication |
| `SNMP` | SNMP monitoring |
| `SOCKS5` | SOCKS5 proxy |
| `Telnet` | Telnet remote access |
| `VNC` | VNC remote desktop |

---

## 9. Container & Microservice Properties `[CVE-backed]`

These properties are derived from Trivy scans of 15 bitnami container images.
Each property maps to real CVEs in `data/vulnerability_db/bitnami_cves.json`.

### 9.1 Language Runtimes

| Property | Description | Key CVEs (CVSS) |
|----------|-------------|-----------------|
| `GoRuntime` | Go standard library (stdlib) | CVE-2023-24538 (9.8), CVE-2024-24790 (9.8), CVE-2024-41110 (9.9) |
| `Java` | Generic JVM runtime | CVE-2025-50059 (8.6), kafka libxml2 CVEs |
| `Python` | Python runtime | CVE-2024-12084 (9.8), CVE-2023-45853 (9.8) |
| `PHP` | PHP runtime (8.x) | WordPress ImageMagick CVEs, Drupal core CVEs |
| `LibCrypto` | libcrypto3 / OpenSSL | CVE-2025-15467 (9.8), CVE-2025-69421 (7.5) |
| `ImageMagick` | ImageMagick image processing library | 10 CRITICAL CVEs ≥ CVSS 9.8 |

### 9.2 Service-Specific Properties

| Property | Description | Chart | CBS Exploit Use |
|----------|-------------|-------|----------------|
| `Redis` | Redis protocol/service (port 6379) | redis | GoRuntime CVEs, unauthenticated access |
| `MongoDB` | MongoDB document store (port 27017) | mongodb | GoRuntime CVEs (CVSS 10.0, 7.5) |
| `MySQL` | MySQL/MariaDB database (port 3306) | mysql | CVE-2026-27459 (9.8) |
| `AuthServer` | OAuth2/OIDC identity provider | keycloak, oauth2-proxy | Keycloak SSRF, OAuthProxy RCE |
| `APIGateway` | API gateway / reverse proxy | kong | Rate-limit bypass, injection |
| `AppServer` | Application tier service | jenkins, grafana, vault | GoRuntime/Java CVEs |
| `WorkerNode` | Message broker / stream processor | kafka, airflow, rabbitmq | libxml2, python CVEs |

### 9.3 Application Frameworks

| Property | Description | Exploit Entries |
|----------|-------------|----------------|
| `WordPressInstall` | WordPress CMS installed | `Solvability.WordPress_ImageMagick`, `Solvability.WordPress_Takeover` |
| `KeycloakService` | Keycloak IAM service | `Solvability.Keycloak_SSRF`, `Solvability.Keycloak_IdentityDump` |

### 9.4 Linux Distribution Variants

| Property | Description | CVE Surface |
|----------|-------------|------------|
| `Alpine` | Alpine Linux (minimal packages) | Near-zero kernel CVEs; PostgreSQL/rabbitmq use this |
| `Debian` | Debian-based containers | Full package tree; source of linux-libc-dev noise |

### 9.5 CVE-Backed Property Usage Examples

```yaml
# nginx entry point — libcrypto CRITICAL CVE
match_properties: [Linux, WebServer, LibCrypto]

# WordPress — ImageMagick CRITICAL CVEs
match_properties: [Linux, PHP, WebServer, ImageMagick]

# Redis cache — GoRuntime CVEs
match_properties: [Linux, DatabaseServer, Redis, GoRuntime]

# Keycloak auth server
match_properties: [Linux, AuthServer, Java, KeycloakService]

# Unauthenticated MongoDB (credential_leak)
match_properties: [Linux, DatabaseServer, MongoDB, Misconfigured]

# Kafka worker
match_properties: [Linux, WorkerNode, Java]
```

---

## 10. Using Properties Correctly

### 8.1 Checklist Before Adding a Property

1. Is it in `identifiers.base_properties`? (Required)
2. Is it assigned to at least one service in `default_properties`? (If not, it won't appear)
3. If used in `match_properties`, does at least one service have ALL the listed properties?
4. If used in a `MUST_HAVE` constraint, is it a property name and not a group name?

### 8.2 Property Specificity Guidelines

More specific `match_properties` = fewer nodes get the exploit = more targeted behavior.

```yaml
# Too broad — applies to ALL Windows nodes:
match_properties: [Windows]

# Well-targeted — applies only to unpatched Win7 domain members:
match_properties: [Windows, Win7, Unpatched, NoLAPS, DomainJoined]

# Too restrictive — may match zero nodes:
match_properties: [Windows, Win7, Unpatched, NoLAPS, DomainJoined, WDigest, SMBv1, PrintSpooler, ADCS]
```

**Recommendation:** Use 2–5 properties in `match_properties` for best coverage.
