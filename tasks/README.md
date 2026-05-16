# Tasks — GLOBALTECH Dataset Generation

5 specialists × 11 configs + 1 meta × 11 configs = **66 total**  
Tier → Phase 2 train count: **small ≤50→5 · medium 50–200→3 · large 200–500→2 · xl 500–1000→1**  
Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Completed

| Config | Agent | Tier | Score |
|--------|-------|:----:|:-----:|
| `snet_perimeter_standalone_v1` | S_Network | medium | 8.3 |
| `slin_cloud_standalone_v1` | S_Linux | large | 8.5 |
| `slin_cloud_meta_v1` | S_Linux | large | 8.5 |
| `swin_serverfarm_standalone_v1` | S_Windows | xl | 8.5 |
| `sid_ad_standalone_v1` | S_Identity | medium | 8.5 |
| ~~`srec_recon_standalone_v1`~~ | ~~S_Recon~~ | ~~xl~~ | ~~9.0~~ |

---

## Queue

### S_Network — 10 pending (1 done)
| File | Tier | Train |
|------|:----:|:-----:|
| [snet/snet_soho_standalone_v1.md](snet/snet_soho_standalone_v1.md) | small | 5 |
| [snet/snet_branch_standalone_v1.md](snet/snet_branch_standalone_v1.md) | small | 5 |
| [snet/snet_dmz_edge_v1.md](snet/snet_dmz_edge_v1.md) | small | 5 |
| [snet/snet_vpn_gateway_v1.md](snet/snet_vpn_gateway_v1.md) | small | 5 |
| [snet/snet_single_fw_v1.md](snet/snet_single_fw_v1.md) | small | 5 |
| [snet/snet_highsec_standalone_v1.md](snet/snet_highsec_standalone_v1.md) | medium | 3 |
| [snet/snet_multivendor_v1.md](snet/snet_multivendor_v1.md) | medium | 3 |
| [snet/snet_datacenter_edge_v1.md](snet/snet_datacenter_edge_v1.md) | large | 2 |
| [snet/snet_enterprise_dual_v1.md](snet/snet_enterprise_dual_v1.md) | large | 2 |
| [snet/snet_enterprise_full_v1.md](snet/snet_enterprise_full_v1.md) | xl | 1 |

### S_Linux — 9 pending (2 done)
| File | Tier | Train |
|------|:----:|:-----:|
| [slin/slin_redis_standalone_v1.md](slin/slin_redis_standalone_v1.md) | small | 5 |
| [slin/slin_jenkins_standalone_v1.md](slin/slin_jenkins_standalone_v1.md) | small | 5 |
| [slin/slin_nodejs_standalone_v1.md](slin/slin_nodejs_standalone_v1.md) | small | 5 |
| [slin/slin_lamp_standalone_v1.md](slin/slin_lamp_standalone_v1.md) | small | 5 |
| [slin/slin_gitlab_standalone_v1.md](slin/slin_gitlab_standalone_v1.md) | small | 5 |
| [slin/slin_cicd_standalone_v1.md](slin/slin_cicd_standalone_v1.md) | medium | 3 |
| [slin/slin_k8s_cluster_v1.md](slin/slin_k8s_cluster_v1.md) | medium | 3 |
| [slin/slin_kafka_worker_v1.md](slin/slin_kafka_worker_v1.md) | medium | 3 |
| [slin/slin_full_cloud_native_v1.md](slin/slin_full_cloud_native_v1.md) | xl | 1 |

### S_Windows — 10 pending (1 done)
| File | Tier | Train |
|------|:----:|:-----:|
| [swin/swin_workstation_vlan_v1.md](swin/swin_workstation_vlan_v1.md) | small | 5 |
| [swin/swin_iis_web_v1.md](swin/swin_iis_web_v1.md) | small | 5 |
| [swin/swin_rdpgw_standalone_v1.md](swin/swin_rdpgw_standalone_v1.md) | small | 5 |
| [swin/swin_office_rce_v1.md](swin/swin_office_rce_v1.md) | small | 5 |
| [swin/swin_netlogon_v1.md](swin/swin_netlogon_v1.md) | small | 5 |
| [swin/swin_serverfarm_mini_v1.md](swin/swin_serverfarm_mini_v1.md) | medium | 3 |
| [swin/swin_exchange_standalone_v1.md](swin/swin_exchange_standalone_v1.md) | medium | 3 |
| [swin/swin_hyperv_standalone_v1.md](swin/swin_hyperv_standalone_v1.md) | medium | 3 |
| [swin/swin_datacenter_v1.md](swin/swin_datacenter_v1.md) | large | 2 |
| [swin/swin_enterprise_v1.md](swin/swin_enterprise_v1.md) | large | 2 |

### S_Identity — 10 pending (1 done)
| File | Tier | Train |
|------|:----:|:-----:|
| [sid/sid_kerberoast_v1.md](sid/sid_kerberoast_v1.md) | small | 5 |
| [sid/sid_asrep_roast_v1.md](sid/sid_asrep_roast_v1.md) | small | 5 |
| [sid/sid_ntlm_relay_v1.md](sid/sid_ntlm_relay_v1.md) | small | 5 |
| [sid/sid_delegation_v1.md](sid/sid_delegation_v1.md) | small | 5 |
| [sid/sid_zerologon_v1.md](sid/sid_zerologon_v1.md) | small | 5 |
| [sid/sid_exchange_adcs_v1.md](sid/sid_exchange_adcs_v1.md) | medium | 3 |
| [sid/sid_adcs_heavy_v1.md](sid/sid_adcs_heavy_v1.md) | medium | 3 |
| [sid/sid_multidomain_v1.md](sid/sid_multidomain_v1.md) | large | 2 |
| [sid/sid_forest_trust_v1.md](sid/sid_forest_trust_v1.md) | large | 2 |
| [sid/sid_full_enterprise_v1.md](sid/sid_full_enterprise_v1.md) | xl | 1 |

### S_Lateral — 11 pending (0 done)
| File | Tier | Train |
|------|:----:|:-----:|
| [slat/slat_ntlm_relay_v1.md](slat/slat_ntlm_relay_v1.md) | small | 5 |
| [slat/slat_winrm_creds_v1.md](slat/slat_winrm_creds_v1.md) | small | 5 |
| [slat/slat_mssql_lateral_v1.md](slat/slat_mssql_lateral_v1.md) | small | 5 |
| [slat/slat_exchange_relay_v1.md](slat/slat_exchange_relay_v1.md) | small | 5 |
| [slat/slat_adcs_cert_v1.md](slat/slat_adcs_cert_v1.md) | small | 5 |
| [slat/slat_multizone_relay_v1.md](slat/slat_multizone_relay_v1.md) | medium | 3 |
| [slat/slat_print_coerce_v1.md](slat/slat_print_coerce_v1.md) | medium | 3 |
| [slat/slat_ldap_passback_v1.md](slat/slat_ldap_passback_v1.md) | medium | 3 |
| [slat/slat_perimeter_to_hq_v1.md](slat/slat_perimeter_to_hq_v1.md) | large | 2 |
| [slat/slat_cloud_to_corp_v1.md](slat/slat_cloud_to_corp_v1.md) | large | 2 |
| [slat/slat_enterprise_full_v1.md](slat/slat_enterprise_full_v1.md) | xl | 1 |

### Meta — 11 pending (0 done)
| File | Curriculum Stage | Train |
|------|:----------------:|:-----:|
| [meta/meta_z4_to_z1_v1.md](meta/meta_z4_to_z1_v1.md) | Stage 1 | 3 |
| [meta/meta_z6_to_z1_v1.md](meta/meta_z6_to_z1_v1.md) | Stage 1 | 3 |
| [meta/meta_z4_perimeter_v1.md](meta/meta_z4_perimeter_v1.md) | Stage 1 | 3 |
| [meta/meta_perimeter_ad_v1.md](meta/meta_perimeter_ad_v1.md) | Stage 2 | 3 |
| [meta/meta_cloud_ad_v1.md](meta/meta_cloud_ad_v1.md) | Stage 2 | 3 |
| [meta/meta_branch_hq_v1.md](meta/meta_branch_hq_v1.md) | Stage 2 | 3 |
| [meta/meta_full_enterprise_v1.md](meta/meta_full_enterprise_v1.md) | Stage 3 | 2 |
| [meta/meta_full_cloud_corp_v1.md](meta/meta_full_cloud_corp_v1.md) | Stage 3 | 2 |
| [meta/meta_stagnation_v1.md](meta/meta_stagnation_v1.md) | Stage 4 | 3 |
| [meta/meta_dual_path_v1.md](meta/meta_dual_path_v1.md) | Stage 4 | 3 |
| [meta/meta_decoy_v1.md](meta/meta_decoy_v1.md) | Stage 4 | 3 |
