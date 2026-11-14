# Coverage matrix

Schema `1.3`, generator `1.3.0`. Floors: 20 atomic, 15 compositional, 15 contextual per authored category.

## Authored categories

| Cat | Name | Atomic | Compositional | Contextual | Malicious | Benign | Layers |
|---|---|---|---|---|---|---|---|
| A | Reconnaissance and information gathering | 30 | 15 | 16 | 61 | 1 | capability, contracts, ifc, semantic |
| B | Unauthorized access and identity abuse | 28 | 15 | 15 | 58 | 2 | capability, contracts, dcbf, ifc, workflow |
| C | Data-related attacks | 30 | 15 | 15 | 60 | 31 | capability, contracts, ifc, workflow |
| D | Filesystem and operating-system attacks | 30 | 15 | 19 | 64 | 42 | capability, contracts, dcbf, ifc, semantic, workflow |
| E | Network and infrastructure attacks | 30 | 15 | 38 | 83 | 13 | capability, contracts, dcbf |
| F | Web application and API attacks | 29 | 15 | 15 | 59 | 18 | capability, contracts, dcbf |
| G | Email, communication and social engineering | 27 | 15 | 15 | 57 | 24 | capability, contracts, dcbf, ifc, semantic |
| H | Financial and transactional attacks | 30 | 15 | 15 | 60 | 27 | capability, contracts, dcbf, hitl, semantic |
| I | Cloud and DevOps attacks | 29 | 15 | 15 | 59 | 25 | capability, contracts, dcbf, hitl, ifc, semantic, workflow |
| J | Persistence and security-control interference | 30 | 15 | 23 | 68 | 4 | capability, contracts, hitl, workflow |
| K | AI-agent-specific attacks | 32 | 19 | 36 | 87 | 69 | capability, dcbf, hitl, ifc, semantic, workflow |
| X | Externally sourced cases (GATE-Union) (imported) | 937 | 0 | 0 | 937 | 48 | capability, contracts, dcbf, semantic, workflow |

## Subcategory matrix

| Category | Subcategory | Name | Atomic | Comp | Ctx | Layers |
|---|---|---|---|---|---|---|
| A | A01 | System reconnaissance | 3 | 0 | 5 | capability, semantic |
| A | A02 | Network discovery | 3 | 2 | 4 | capability, semantic |
| A | A03 | Service enumeration | 3 | 2 | 0 | capability |
| A | A04 | Account enumeration | 3 | 2 | 4 | capability, semantic |
| A | A05 | Technology fingerprinting | 3 | 0 | 0 | capability |
| A | A06 | API reconnaissance | 3 | 0 | 0 | capability |
| A | A07 | Cloud reconnaissance | 3 | 2 | 0 | capability |
| A | A08 | Permission discovery | 3 | 2 | 0 | capability |
| A | A09 | Metadata harvesting | 3 | 2 | 0 | contracts |
| A | A10 | OSINT collection | 3 | 3 | 3 | ifc, semantic |
| B | B01 | Credential theft | 3 | 3 | 0 | capability, ifc |
| B | B02 | Credential stuffing | 2 | 2 | 0 | dcbf |
| B | B03 | Password spraying | 2 | 1 | 0 | dcbf |
| B | B04 | Token theft | 3 | 1 | 0 | capability |
| B | B05 | Session hijacking | 3 | 1 | 3 | capability |
| B | B06 | Privilege escalation | 3 | 2 | 0 | capability, workflow |
| B | B07 | Privilege abuse | 3 | 1 | 4 | capability, contracts |
| B | B08 | Identity impersonation | 3 | 1 | 4 | capability, workflow |
| B | B09 | Account takeover | 3 | 1 | 0 | capability |
| B | B10 | Cross-tenant access | 3 | 2 | 4 | capability |
| D | D01 | Unauthorized file reading | 3 | 3 | 5 | capability, ifc, semantic |
| D | D02 | Unauthorized file modification | 3 | 3 | 4 | contracts, semantic |
| D | D03 | Unauthorized file deletion | 3 | 1 | 2 | contracts |
| D | D04 | Arbitrary file creation | 3 | 0 | 0 | contracts |
| D | D05 | Path traversal | 3 | 2 | 2 | contracts |
| D | D06 | Command execution abuse | 3 | 2 | 0 | contracts |
| D | D07 | Script execution abuse | 3 | 1 | 0 | contracts, workflow |
| D | D08 | Configuration manipulation | 3 | 1 | 6 | contracts, semantic, workflow |
| D | D09 | Environment variable disclosure | 3 | 1 | 0 | ifc |
| D | D10 | Resource exhaustion | 3 | 1 | 0 | dcbf |
| F | F01 | Unauthorized API invocation | 3 | 2 | 0 | capability |
| F | F02 | API parameter manipulation | 3 | 2 | 5 | contracts |
| F | F03 | Broken access control exploitation | 3 | 2 | 0 | capability |
| F | F04 | Injection attacks | 3 | 3 | 0 | contracts |
| F | F05 | Cross-site scripting | 3 | 1 | 4 | contracts |
| F | F06 | Cross-site request forgery | 3 | 1 | 0 | contracts |
| F | F07 | Server-side request forgery | 3 | 1 | 3 | contracts |
| F | F08 | Business logic abuse | 3 | 2 | 3 | contracts |
| F | F09 | API rate-limit abuse | 2 | 1 | 0 | dcbf |
| F | F10 | Unauthorized webhook manipulation | 3 | 0 | 0 | capability |
| C | C01 | Data exfiltration | 3 | 3 | 4 | ifc |
| C | C02 | Unauthorized data access | 3 | 2 | 0 | capability, contracts, ifc |
| C | C03 | Sensitive information disclosure | 3 | 2 | 4 | ifc |
| C | C04 | Database manipulation | 3 | 1 | 0 | contracts |
| C | C05 | Data deletion | 3 | 2 | 0 | contracts, workflow |
| C | C06 | Data corruption | 3 | 0 | 0 | contracts |
| C | C07 | Data aggregation abuse | 3 | 2 | 1 | ifc |
| C | C08 | Intellectual property theft | 3 | 1 | 0 | ifc |
| C | C09 | Cross-user data leakage | 3 | 1 | 3 | capability, ifc |
| C | C10 | Backup exfiltration | 3 | 1 | 3 | capability, ifc |
| G | G01 | Phishing | 3 | 2 | 3 | ifc, semantic |
| G | G02 | Spear phishing | 2 | 0 | 2 | semantic |
| G | G03 | Business email compromise | 3 | 2 | 1 | contracts, semantic |
| G | G04 | Spam generation | 2 | 1 | 2 | dcbf, semantic |
| G | G05 | Unauthorized email forwarding | 3 | 1 | 0 | capability |
| G | G06 | Contact harvesting | 3 | 3 | 0 | ifc |
| G | G07 | Social engineering | 2 | 0 | 3 | semantic |
| G | G08 | Misinformation distribution | 3 | 2 | 2 | semantic |
| G | G09 | Impersonation campaigns | 3 | 2 | 2 | semantic |
| G | G10 | Unauthorized communication | 3 | 2 | 0 | capability, ifc |
| E | E01 | Unauthorized network connections | 3 | 2 | 6 | capability, contracts |
| E | E02 | Network traffic interception | 3 | 1 | 0 | capability |
| E | E03 | Man-in-the-middle activity | 3 | 1 | 0 | capability, contracts |
| E | E04 | DNS manipulation | 3 | 2 | 0 | contracts |
| E | E05 | Service disruption | 3 | 1 | 6 | contracts, dcbf |
| E | E06 | Distributed denial of service | 3 | 1 | 0 | dcbf |
| E | E07 | Internal network access | 3 | 2 | 15 | capability, contracts |
| E | E08 | Lateral movement | 3 | 3 | 6 | capability, contracts |
| E | E09 | Unauthorized tunneling | 3 | 1 | 0 | capability, contracts |
| E | E10 | Firewall policy abuse | 3 | 1 | 5 | capability, contracts |
| I | I01 | Unauthorized cloud provisioning | 3 | 2 | 0 | capability, ifc |
| I | I02 | IAM policy manipulation | 3 | 1 | 0 | capability |
| I | I03 | Secret exposure | 3 | 2 | 4 | ifc |
| I | I04 | Container manipulation | 3 | 2 | 0 | contracts |
| I | I05 | Kubernetes privilege abuse | 3 | 1 | 0 | capability |
| I | I06 | CI/CD pipeline manipulation | 3 | 1 | 3 | contracts |
| I | I07 | Artifact poisoning | 3 | 2 | 0 | contracts |
| I | I08 | Deployment manipulation | 3 | 1 | 3 | capability, contracts, semantic, workflow |
| I | I09 | Infrastructure destruction | 3 | 2 | 5 | capability, hitl |
| I | I10 | Cloud resource abuse | 2 | 1 | 0 | dcbf |
| K | K01 | Direct prompt injection | 3 | 0 | 2 | semantic |
| K | K02 | Indirect prompt injection | 3 | 1 | 2 | semantic |
| K | K03 | Tool misuse | 3 | 0 | 0 | capability |
| K | K04 | Tool privilege escalation | 0 | 2 | 0 | workflow |
| K | K05 | Tool-chain abuse | 0 | 3 | 0 | workflow |
| K | K06 | Confused deputy | 0 | 1 | 0 | workflow |
| K | K07 | Goal hijacking | 0 | 0 | 8 | semantic, workflow |
| K | K08 | Plan manipulation | 0 | 1 | 2 | workflow |
| K | K09 | Memory poisoning | 3 | 1 | 2 | semantic, workflow |
| K | K10 | Context poisoning | 0 | 1 | 1 | semantic, workflow |
| K | K11 | Multi-agent collusion | 0 | 1 | 0 | workflow |
| K | K12 | Unauthorized delegation | 3 | 1 | 1 | workflow |
| K | K13 | Recursive agent spawning | 2 | 1 | 1 | dcbf |
| K | K14 | Trust-boundary violation | 3 | 1 | 1 | ifc |
| K | K15 | Human approval manipulation | 3 | 1 | 2 | hitl |
| K | K16 | Semantic policy evasion | 3 | 1 | 3 | semantic |
| K | K17 | Action replay | 3 | 1 | 1 | workflow |
| K | K18 | Excessive agency | 3 | 1 | 4 | workflow |
| K | K19 | Goal drift | 0 | 0 | 4 | semantic |
| K | K20 | Tool-output exploitation | 0 | 1 | 2 | semantic, workflow |
| H | H01 | Unauthorized purchases | 3 | 3 | 4 | capability, contracts, hitl |
| H | H02 | Unauthorized fund transfers | 3 | 3 | 4 | capability, contracts, hitl, semantic |
| H | H03 | Payment manipulation | 3 | 1 | 4 | contracts |
| H | H04 | Invoice fraud | 3 | 2 | 0 | contracts |
| H | H05 | Subscription abuse | 3 | 1 | 0 | contracts, dcbf |
| H | H06 | Refund abuse | 3 | 1 | 0 | contracts |
| H | H07 | Financial data manipulation | 3 | 1 | 0 | contracts |
| H | H08 | Cryptocurrency transaction abuse | 3 | 1 | 0 | capability, contracts |
| H | H09 | Trading manipulation | 3 | 1 | 3 | capability, contracts, semantic |
| H | H10 | Resource procurement abuse | 3 | 1 | 0 | hitl |
| J | J01 | Unauthorized scheduled tasks | 3 | 3 | 2 | capability, contracts, workflow |
| J | J02 | Startup configuration manipulation | 3 | 2 | 7 | contracts |
| J | J03 | Unauthorized service creation | 3 | 1 | 0 | capability, contracts |
| J | J04 | Security configuration modification | 3 | 1 | 2 | capability, contracts |
| J | J05 | Audit log manipulation | 3 | 1 | 2 | contracts |
| J | J06 | Monitoring interference | 3 | 1 | 0 | capability, contracts |
| J | J07 | Security tool interference | 3 | 1 | 0 | contracts |
| J | J08 | Policy modification | 3 | 1 | 2 | capability, contracts |
| J | J09 | Unauthorized agent delegation | 3 | 2 | 8 | workflow |
| J | J10 | Persistent unauthorized access | 3 | 2 | 0 | contracts, hitl |
| X | X01 | InjecAgent tool-response injection | 731 | 0 | 0 | contracts |
| X | X02 | Gate-suite capability or privilege violation | 60 | 0 | 0 | capability |
| X | X03 | Gate-suite declarative contract violation | 13 | 0 | 0 | contracts |
| X | X04 | Gate-suite semantic policy violation | 18 | 0 | 0 | semantic |
| X | X05 | Gate-suite workflow (DFA) violation | 5 | 0 | 0 | workflow |
| X | X06 | Gate-suite runtime barrier violation | 18 | 0 | 0 | dcbf |
| X | X07 | SafeClawBench unsafe instruction | 92 | 0 | 0 | contracts |
| X | X08 | Benign externally sourced case | 0 | 0 | 0 | - |
