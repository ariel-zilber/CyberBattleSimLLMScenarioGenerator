# S-LAT-M03: LDAP Attribute Write — Shadow Credentials
**Agent:** S_Lateral
**File:** `slat_ldap_passback_v1.yaml`
**Tier:** medium · 50–200 nodes · 3 train scenarios
**Status:** [ ] not started

Shadow Credentials attack: LDAP msDS-KeyCredentialLink write on a pre-owned DomainController → PKINIT authentication → cross-zone to Z8 PAM node. Tests cloud IAM → LDAP write path (Z6 → Z1 → Z8).
