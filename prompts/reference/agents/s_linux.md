# S_Linux - Linux, Cloud, and Container Specialist

This file is the authoritative prompt reference for `s_linux` scenario generation.
It is aligned to `/home/ariel/Documents/thesis/CyberBattleSim/cyberbattle/data/global_vocabulary.yaml`.

## Role

Exploit Linux services, cloud workloads, containers, CI/CD systems, and cloud-native infrastructure.

Domain boundary: Linux servers, container runtimes, Kubernetes, AWS services, Redis/PostgreSQL/MySQL, GitLab, Jenkins, RabbitMQ, Kafka, Vault, Grafana, and related cloud services.

Training scenarios for this specialist must be specialist-style fixed-pair compatible scenarios. In meta scenarios, the same collections define the specialist's usable action and observation surface.

## Fixed Action Collection

The specialist has exactly 50 actions:

| Action kind | Count |
|---|---:|
| Local vulnerabilities | 19 |
| Remote vulnerabilities | 17 |
| Connect ports | 14 |
| Total | 50 |

### Local Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.Docker_Socket_Escape` |
| 1 | `Solvability.Kubernetes_HostPID_Escape` |
| 2 | `Solvability.Container_ProcMount_Escape` |
| 3 | `Solvability.Redis_Noauth_Config_Rewrite` |
| 4 | `Solvability.Hadoop_FileUtil_Inject` |
| 5 | `Solvability.Bundler_DNSHijack` |
| 6 | `Solvability.WordPressDB_Creds` |
| 7 | `Solvability.Container_EnvVars` |
| 8 | `Solvability.AWS_CredFile` |
| 9 | `Solvability.VaultToken_EnvVar` |
| 10 | `Solvability.KubeServiceAccount` |
| 11 | `Solvability.MongoDB_NoAuth` |
| 12 | `Solvability.Redis_NoAuth` |
| 13 | `Solvability.Keycloak_AdminCreds` |
| 14 | `Solvability.Kafka_ConfigLeak` |
| 15 | `Solvability.Grafana_DataSource` |
| 16 | `Solvability.Vault_Unsealed` |
| 17 | `Solvability.Airflow_Connections` |
| 18 | `Solvability.SSH_PrivKey_Theft` |

### Remote Vulnerabilities

| Slot | Identifier |
|---:|---|
| 0 | `Solvability.Concourse_ContainerEscape` |
| 1 | `Solvability.ApacheSpark_PrivEsc` |
| 2 | `Solvability.SnakeYAML_Deserialization` |
| 3 | `Solvability.ImageMagick_ShellInject` |
| 4 | `Solvability.MySQL2_SQLInject_1` |
| 5 | `Solvability.MySQL2_SQLInject_2` |
| 6 | `Solvability.JavaDeserialize_RCE_1` |
| 7 | `Solvability.JavaDeserialize_RCE_2` |
| 8 | `Solvability.GhostCMS_CSV_Injection` |
| 9 | `Solvability.ApacheAvro_Deserialization` |
| 10 | `Solvability.LibSSH_OpenSSL_RCE` |
| 11 | `Solvability.GoGoProtobuf_Deserialization` |
| 12 | `Solvability.Zlib_IntOverflow` |
| 13 | `Solvability.OpenEXR_OOB_Write` |
| 14 | `Solvability.PgDump_UntrustedData` |
| 15 | `Solvability.Elasticsearch_Groovy_RCE` |
| 16 | `Solvability.NodeJS_IP_SSRF` |

### Connect Ports

| Slot | Identifier |
|---:|---|
| 0 | `SSH` |
| 1 | `HTTP` |
| 2 | `HTTPS` |
| 3 | `FTP` |
| 4 | `SMTP` |
| 5 | `DNS` |
| 6 | `MSSQL` |
| 7 | `MySQL` |
| 8 | `PostgreSQL` |
| 9 | `VNC` |
| 10 | `Telnet` |
| 11 | `SNMP` |
| 12 | `NetBIOS` |
| 13 | `WMI` |

## Observation Context Collection

The scenario generator should preferentially use these service and property identifiers for this specialist. These are not extra actions; they are the specialist's observation context and vocabulary guidance.

| Context type | Count |
|---|---:|
| Service IDs | 30 |
| Property IDs | 52 |

### Service IDs

| Slot | Identifier |
|---:|---|
| 0 | `AWSWebServer` |
| 1 | `AWSAppServer` |
| 2 | `AWSRedis` |
| 3 | `AWSPostgreSQL` |
| 4 | `AWSMySQL` |
| 5 | `AWSElasticsearch` |
| 6 | `AWSCassandra` |
| 7 | `AWSWorkerNode` |
| 8 | `AWSRabbitMQ` |
| 9 | `AWSAuthServer` |
| 10 | `AWSGitLab` |
| 11 | `AWSJenkins` |
| 12 | `sshd` |
| 13 | `httpd` |
| 14 | `apache2` |
| 15 | `nginx` |
| 16 | `ftpd` |
| 17 | `mysqld` |
| 18 | `postgres_svc` |
| 19 | `docker_api` |
| 20 | `kubelet` |
| 21 | `redis_svc` |
| 22 | `memcached_svc` |
| 23 | `elastic_svc` |
| 24 | `grafana_svc` |
| 25 | `jenkins_svc` |
| 26 | `gitlab_svc` |
| 27 | `nginx_proxy` |
| 28 | `vault_svc` |
| 29 | `consul_svc` |

### Property IDs

| Slot | Identifier |
|---:|---|
| 0 | `Linux` |
| 1 | `Unix` |
| 2 | `Ubuntu` |
| 3 | `CentOS` |
| 4 | `Debian` |
| 5 | `Alpine` |
| 6 | `RedHat` |
| 7 | `Kali` |
| 8 | `DeveloperWorkstation` |
| 9 | `WebServer` |
| 10 | `NginxServer` |
| 11 | `ApacheServer` |
| 12 | `LoadBalancer` |
| 13 | `ReverseProxy` |
| 14 | `FTPServer` |
| 15 | `AppServer` |
| 16 | `APIGateway` |
| 17 | `Middleware` |
| 18 | `CacheServer` |
| 19 | `MessageBroker` |
| 20 | `BackupServer` |
| 21 | `DatabaseServer` |
| 22 | `MySQLServer` |
| 23 | `PostgreSQLServer` |
| 24 | `MongoDBServer` |
| 25 | `RedisServer` |
| 26 | `ElasticsearchServer` |
| 27 | `NoSQL` |
| 28 | `PostgreSQL` |
| 29 | `Kubernetes` |
| 30 | `Pod` |
| 31 | `Container` |
| 32 | `WorkerNode` |
| 33 | `K8sCluster` |
| 34 | `CloudInstance` |
| 35 | `AWS` |
| 36 | `EC2` |
| 37 | `EKS` |
| 38 | `CloudLambda` |
| 39 | `CloudRDS` |
| 40 | `IMDS` |
| 41 | `IMDSv1` |
| 42 | `Serverless` |
| 43 | `etcd` |
| 44 | `DMZ` |
| 45 | `Unpatched` |
| 46 | `Misconfigured` |
| 47 | `LocalAdmin` |
| 48 | `AuthServer` |
| 49 | `IdentityProvider` |
| 50 | `OracleServer` |
| 51 | `MailServer` |

## Generation Rules

- Use only identifiers from this file and the shared global vocabulary.
- Do not invent probe actions such as `Remote.Probe.*`.
- Do not use legacy scenario-only identifiers such as `External.*` or `Local.*`.
- Do not use off-vocabulary ports such as `BGP` or `Redis`; represent those concepts through service IDs or properties when needed.
- Every vulnerability emitted for this specialist must be one of the local or remote IDs listed above.
- Connect actions are represented only by the listed port names.
- Credentials are runtime objects, not vocabulary entries. They should target one of the listed services/ports and support valid fixed-pair connect actions.
- Multi-goal scenarios are allowed, but specialist actions must remain inside this 50-action collection.

## Scenario Intent

Use Linux/cloud remote exploits and local credential or secret extraction to progress through cloud and container tiers.
