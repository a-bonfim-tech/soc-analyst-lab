# SOC-2026-006 — Evidence Manifest

## Evidence state

This manifest records SHA-256 hashes for the reviewed public repository artifacts of SOC-2026-006.

Raw Microsoft Defender and Microsoft Sentinel exports remain private and are not included in the public repository.

## Public artifact hashes

| Artifact | SHA-256 |
|---|---|
| `02-alerts/SOC-2026-006/alert-record.md` | `993d5d1963b0881e955f2b614a8ff230b085cdbb1ca45a96afeb6608042826f2` |
| `03-investigations/SOC-2026-006/findings.md` | `4953b23f6499655be2c3e030535d09b56027906f48c8ef2899148f27114c92db` |
| `03-investigations/SOC-2026-006/investigation.md` | `81a3a7911aba66b36c68ba5970c4eed6d9977074d9cd9ec16e9d922e9c9a8d5f` |
| `03-investigations/SOC-2026-006/ticket.md` | `738281c838f0c7420b363528d14490ea23009e5227d5961edeec55eb2bab5ca0` |
| `03-investigations/SOC-2026-006/timeline.csv` | `77a807f2fc221018fc3d130c64f2df01589b90e73878e31a43e3835194e3f5f9` |
| `04-detection-rules/kql/SOC-2026-006/README.md` | `12014f522528874f7ee58e9d4f6160c26ef11ded3475e10204b0d8b172261a14` |
| `04-detection-rules/kql/SOC-2026-006/defender-advanced-hunting-execution-validation.kql` | `571210db19614ccb8359b0bb3a923275485998811d9682e9e9f643543020b1df` |
| `04-detection-rules/kql/SOC-2026-006/device-process-investigation-execution-validation.kql` | `f4cd3d780ede97ce7427de24b463f41d350ce6818b3a61a7c5afbc4af9787c8f` |
| `04-detection-rules/kql/SOC-2026-006/device-process-investigation.kql` | `66b5eaddc904ae0701ac308a37b0a84b16cb32f29b339267912ae42725a8475c` |
| `04-detection-rules/kql/SOC-2026-006/security-alert-correlation.kql` | `d79b91fa522a472af796b38890910f9b06f243a83d47d72974b4418145bc1948` |
| `04-detection-rules/kql/SOC-2026-006/security-alert-execution-validation.kql` | `013d4df32585dd0a4613ddab37966a5a69ccca99181d56f713150bc09fb598b5` |
| `04-detection-rules/kql/SOC-2026-006/security-incident-correlation.kql` | `71709a73c40d7901186b0041a506821b00a2c23d776fc5bdfcf42ea261af3050` |
| `04-detection-rules/kql/SOC-2026-006/security-incident-execution-validation.kql` | `c0cf913facfa7fdc6b4ea33e26a0e7fc18c882a3d10c2e82606647cd670a2161` |
| `09-reports/SOC-2026-006/incident-report.md` | `58b0f2eeaa535d63e38b9d94ee8978b03f732e23599ef9c5b973bf2a26bd48b1` |
| `10-evidence/SOC-2026-006/authorization-and-execution-boundary.md` | `5cb6e9f5bb7f79e3560a3539991faad6447b21fd513aa5c4855e5a742a04176c` |
| `10-evidence/SOC-2026-006/defender-advanced-hunting.md` | `ea9ac7211a88a17758b01bb3ce868e804fd1592c376f8a125aa1ad37edeea2ef` |
| `10-evidence/SOC-2026-006/endpoint-state.md` | `74a9b83e0e45a9369e219dfbbd49d11066b1cc8d8defb73722bbbfccb440681b` |
| `10-evidence/SOC-2026-006/sentinel-securityalert.md` | `0190ec59a65fd45c57317ed78b677b4748a37c56af094431f2fa81499f862665` |
| `10-evidence/SOC-2026-006/sentinel-securityincident.md` | `20f5081ce7fe73acaf6b09fbd4ad87c052e19ecb92cab5023e5837dd397a4e38` |

## Integrity boundary

- A listed SHA-256 establishes integrity of that repository artifact at the time this manifest was generated.
- Private raw evidence remains outside the public repository and is referenced by reviewed evidence documents where applicable.
- Sensitive tenant, subscription, workspace, device, user, alert and incident identifiers remain excluded where unnecessary.
- The missing contemporaneous endpoint-onboarding artifact remains an explicit evidence gap.
- The missing contemporaneous formal EDR test execution window remains an explicit evidence gap.
- This manifest does not convert either missing evidence item into a satisfied contract gate.
- Exact candidate-commit repository validation remains pending until the final candidate commit exists.
