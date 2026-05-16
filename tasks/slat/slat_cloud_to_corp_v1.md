# S-LAT-L02: Cloud to Corporate Credential Bridge
**Agent:** S_Lateral
**File:** `slat_cloud_to_corp_v1.yaml`
**Tier:** large · 200–500 nodes · 2 train scenarios
**Status:** [ ] not started

Z6 AWS → Z1 HQ crossing via cloud IAM credentials. S_Lateral fires `Solvability.Container_EnvVars` or `Solvability.AWS_CredFile` (LOCAL credential_leak) on the breach AWSAppServer to extract an IAM role token; then uses LDAP attribute write (Seamless SSO abuse) or Shadow Credentials to authenticate into Z1. Tests the cloud-to-corp crossing that S_Lateral owns in the meta attack path. Credential store starts empty — no pre-seeded IAM token.
