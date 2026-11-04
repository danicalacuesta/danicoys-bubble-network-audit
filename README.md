# Danicoy's Bubble

A local sandbox for **network design and security auditing**. It pairs a three-tier network defined as code with a standalone Python auditor that scans firewall rules for dangerous configurations such as SSH or RDP open to the public internet.

## Objective

Misconfigured firewall rules are one of the most common and most preventable causes of security incidents. This project practices two core cloud operations skills:

1. **Designing** a segmented network with least-privilege access between tiers.
2. **Auditing** firewall rule sets automatically, so violations are caught by a script.

## Architecture

A single virtual network is split into three isolated tiers. Traffic may only flow downward, one tier at a time.

```
                      Public Internet
                            |
                      443 (HTTPS) only
                            v
        +-----------------------------------------+
        |  bubble-core-vnet        10.0.0.0/16    |
        |                                         |
        |  +-----------------------------------+  |
        |  | snet-web   10.0.1.0/24            |  |
        |  | Tier 1: web / ingress             |  |
        |  +-----------------+-----------------+  |
        |                    | 8080               |
        |  +-----------------v-----------------+  |
        |  | snet-app   10.0.2.0/24            |  |
        |  | Tier 2: application logic         |  |
        |  +-----------------+-----------------+  |
        |                    | 1433               |
        |  +-----------------v-----------------+  |
        |  | snet-db    10.0.3.0/24            |  |
        |  | Tier 3: isolated database         |  |
        |  | NSG: nsg-database-protection      |  |
        |  +-----------------------------------+  |
        +-----------------------------------------+
```

| Tier | Subnet | CIDR | Usable IPs* | Allowed inbound |
|------|--------|------|-------------|-----------------|
| Web | `snet-web` | `10.0.1.0/24` | 251 | HTTPS from the internet |
| App | `snet-app` | `10.0.2.0/24` | 251 | Web tier only |
| Database | `snet-db` | `10.0.3.0/24` | 251 | App tier only, on the database port |

\*Five addresses in each subnet are reserved by the platform, so a /24 yields 251 usable addresses rather than 256.

The database tier is protected by a network security group (NSG) that follows a zero-trust pattern: one explicit allow rule from the app subnet, then a deny-all rule for everything else.

## Repository layout

```
danicoys-bubble/
├── network.tf            # Terraform definition of the VNet, subnets, and NSG
├── firewall_rules.json   # Mock rule export with compliant and non-compliant rules for application 
├── audit_nsg.py          # Standalone auditor (Python standard library only)
└── README.md
```

## Local setup

### 1. Get the project

```powershell
git clone <your-repository-url> danicoys-bubble
cd danicoys-bubble
```

### 2. Run the security audit

```powershell
python audit_nsg.py
```

Options:

```powershell
python audit_nsg.py path\to\other_rules.json   # audit a different file
python audit_nsg.py --no-color                 # plain text, useful for logs
```

The script exits with `0` when there are no critical or high findings, `1` when there are, and `2` when the input file cannot be read. That makes it easy to use as a pipeline check later.

### 3. Validate the network design (optional)

```powershell
terraform init -backend=false
terraform fmt -check
terraform validate
```

`validate` checks syntax and references offline. The configuration is a design reference and is not intended to be deployed.

## How the audit works

The auditor reads each rule, normalizes it, and applies a small set of policies.

**Parsing.** Port fields are normalized from `22`, `20-25`, `80,443`, or `*` into numeric ranges, so a rule like `3380-3400` is correctly recognized as covering port 3389. Sources are classified as **public** if they are `*`, `Any`, `Internet`, `0.0.0.0/0`, `::/0`, or any network with a prefix length of 0.

**Scope.** Only **inbound allow** rules can create exposure. Deny rules are marked as passing, and outbound rules are not evaluated.

**Policies:**

| Severity | Condition | Example |
|----------|-----------|---------|
| CRITICAL | A remote administration port (SSH 22, Telnet 23, RDP 3389, VNC 5900, WinRM 5985/5986) is reachable from the public internet | `Allow-SSH-From-Internet` |
| CRITICAL | All ports are open to the public internet | `Allow-All-Inbound` |
| HIGH | A database port (1433, 1521, 3306, 5432, 6379, 27017) is reachable from the public internet | `Allow-SQL-From-Internet` |
| MEDIUM | An unrecognized port is exposed publicly without review | `Allow-Custom-App-Port` |
| MEDIUM | All ports are allowed from a broad internal range | `Allow-VNet-All-Ports` |
| MEDIUM | An NSG has no explicit deny-all inbound rule | `nsg-legacy-jumpbox` |
| LOW | Cleartext HTTP (80) is exposed publicly | `Allow-HTTP-Inbound` |

HTTPS (443) from the internet is treated as compliant, as are rules scoped to specific internal subnets.

## First Sample Output

Output from `python audit_nsg.py --no-color` against the included dataset:

```
==============================================================================
 DANICOY'S BUBBLE - NETWORK SECURITY AUDIT REPORT
==============================================================================
 Source file : firewall_rules.json
 Rules read  : 16  (pass 7 | fail 8 | not evaluated 1)

 SUMMARY
------------------------------------------------------------------------------
  CRITICAL  4
  HIGH      1
  MEDIUM    3
  LOW       1

 RULE RESULTS
------------------------------------------------------------------------------
  ID      NSG                      RULE                                PRI  STATUS
  FW-006  nsg-app-tier             Allow-Web-Tier-To-App               100  PASS
  FW-007  nsg-app-tier             Allow-RDP-From-Any                  110  FAIL
  FW-008  nsg-app-tier             Allow-VNet-All-Ports                120  FAIL
  FW-009  nsg-app-tier             Deny-All-Other-Inbound             4096  PASS
  FW-010  nsg-database-protection  Allow-App-Tier-To-DB                100  PASS
  FW-011  nsg-database-protection  Allow-SQL-From-Internet             110  FAIL
  FW-012  nsg-database-protection  Deny-All-Other-Inbound             4096  PASS
  FW-013  nsg-legacy-jumpbox       Allow-All-Inbound                   100  FAIL
  FW-014  nsg-legacy-jumpbox       Allow-Remote-Desktop-Range          110  FAIL
  FW-015  nsg-legacy-jumpbox       Allow-Custom-App-Port               120  FAIL
  FW-016  nsg-legacy-jumpbox       Allow-Outbound-HTTPS                200  SKIP
  FW-001  nsg-web-tier             Allow-HTTPS-Inbound                 100  PASS
  FW-002  nsg-web-tier             Allow-HTTP-Inbound                  110  FAIL
  FW-003  nsg-web-tier             Allow-SSH-From-Internet             120  FAIL
  FW-004  nsg-web-tier             Allow-SSH-From-Management-Subnet    130  PASS
  FW-005  nsg-web-tier             Deny-All-Other-Inbound             4096  PASS

 FINDINGS
------------------------------------------------------------------------------
  [CRITICAL] FW-007 | nsg-app-tier / Allow-RDP-From-Any
      Issue : RDP (port 3389) is open to the public internet.
      Fix   : Restrict the source to a management subnet or VPN/bastion range.

  [CRITICAL] FW-013 | nsg-legacy-jumpbox / Allow-All-Inbound
      Issue : All ports are open to the public internet (includes SSH, RDP and databases).
      Fix   : Delete this rule and allow only the specific ports the tier needs.

  [CRITICAL] FW-014 | nsg-legacy-jumpbox / Allow-Remote-Desktop-Range
      Issue : RDP (port 3389) is open to the public internet.
      Fix   : Restrict the source to a management subnet or VPN/bastion range.

  [CRITICAL] FW-003 | nsg-web-tier / Allow-SSH-From-Internet
      Issue : SSH (port 22) is open to the public internet.
      Fix   : Restrict the source to a management subnet or VPN/bastion range.

  [HIGH] FW-011 | nsg-database-protection / Allow-SQL-From-Internet
      Issue : SQL Server (port 1433) is open to the public internet.
      Fix   : Allow only the application subnet as the source.

  [MEDIUM] FW-008 | nsg-app-tier / Allow-VNet-All-Ports
      Issue : All ports are allowed from a broad internal source (no least-privilege scoping).
      Fix   : Replace with explicit per-service port rules between tiers.

  [MEDIUM] FW-015 | nsg-legacy-jumpbox / Allow-Custom-App-Port
      Issue : Port(s) 8443 are exposed to the public internet without review.
      Fix   : Confirm the service must be public; otherwise restrict the source range.

  [MEDIUM] nsg-legacy-jumpbox (NSG-level check)
      Issue : No explicit deny-all inbound rule at the end of the rule set.
      Fix   : Add a low-priority (e.g. 4096) rule denying all other inbound traffic.

  [LOW] FW-002 | nsg-web-tier / Allow-HTTP-Inbound
      Issue : HTTP (port 80) exposes unencrypted traffic to the internet.
      Fix   : Redirect to HTTPS (443) and remove the cleartext rule.

==============================================================================
 RESULT: FAIL  (4 critical, 1 high, 3 medium, 1 low)
==============================================================================
```

## Extending the project

- Add rules to `firewall_rules.json` and re-run the audit to see how each one is classified.
- Add ports to `MANAGEMENT_PORTS` or `DATABASE_PORTS` in `audit_nsg.py` to tighten the policy.
- Add a check for duplicate rule priorities within an NSG.
- Export findings as JSON or CSV for tracking over time.
- Add unit tests with `pytest` for the port-range and source-classification helpers.

## Limitations

- The auditor evaluates rules individually and does not simulate full rule-order precedence between allow and deny rules.
- Only inbound rules are checked.
- The rule schema is a simplified model and may need adapting for other export formats.

## Skills demonstrated

Network segmentation and CIDR planning, infrastructure as code, least-privilege and zero-trust design, security rule analysis, and Python scripting with the standard library.
