# S-LAT-L02: Cloud to Corporate Credential Bridge
**Agent:** S_Lateral
**File:** `slat_cloud_to_corp_v1.yaml`
**Tier:** large · 200–500 nodes · 2 train scenarios
**Status:** [ ] not started

Z6 AWS → Z1 HQ crossing via cloud IAM credentials. Pre-owned AWSAppServer holds an IAM role token; agent must use LDAP attribute write (Seamless SSO abuse) or Shadow Credentials to authenticate into Z1. Tests the cloud-to-corp crossing that S_Lateral owns in the meta attack path.
