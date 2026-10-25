"""
Sentinel/app/services/real_cyber_skills.py — Real Cybersecurity Skills Layer.

The structured-security-skill model: every skill carries its procedural
workflow *and* its cross-framework mapping, so Sentinel can select skills for
an incident, score detection coverage, compose a response playbook, and prove
that an offensive capability was only used inside an authorized scope.

Real working implementations:
- ATTACK_TACTICS / TECHNIQUE_TACTICS / CSF_CATEGORIES / D3FEND / ATLAS /
  AI_RMF / F3 reference tables
- FrameworkMapping + SecuritySkill + SkillCatalog (searchable, 34 domains)
- TechniqueResolver: sub-technique normalisation, tactic resolution, kill-chain
  ordering, technique families
- NistCsfAssessor: maturity scoring, category/function roll-up, gap analysis
- DetectionCoverageEngine: weighted coverage per tactic, gaps, recommendations
- SkillRecommender: indicator-driven ranking with a score breakdown
- PlaybookComposer: phased response playbook with framework coverage
- AuthorizationScope: rules-of-engagement gate (CIDR / glob / window / tier)
- FraudMapper: MITRE F3 positioning and monetisation mapping
- IncidentReport: severity model, crosswalk and markdown rendering
- CyberSkillsEngine: facade used by Sentinel pipelines
"""
from __future__ import annotations

import fnmatch
import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable


# ── Framework reference data ──────────────────────────────────────────────

ATTACK_TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0112": "Defense Impairment",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Kill-chain order used for ordering findings and playbooks.
TACTIC_ORDER: dict[str, int] = {
    name: index for index, name in enumerate(ATTACK_TACTICS.values())
}

TECHNIQUE_TACTICS: dict[str, list[str]] = {
    "T1593": ["Reconnaissance"],
    "T1592": ["Reconnaissance"],
    "T1590": ["Reconnaissance"],
    "T1595": ["Reconnaissance"],
    "T1583": ["Resource Development"],
    "T1587": ["Resource Development"],
    "T1608": ["Resource Development"],
    "T1566": ["Initial Access"],
    "T1189": ["Initial Access"],
    "T1190": ["Initial Access"],
    "T1133": ["Initial Access"],
    "T1078": ["Initial Access", "Persistence", "Privilege Escalation"],
    "T1195": ["Initial Access"],
    "T1200": ["Initial Access"],
    "T1059": ["Execution"],
    "T1203": ["Execution"],
    "T1204": ["Execution"],
    "T1106": ["Execution"],
    "T1053": ["Execution", "Persistence", "Privilege Escalation"],
    "T1569": ["Execution"],
    "T1055": ["Stealth", "Privilege Escalation"],
    "T1547": ["Persistence", "Privilege Escalation"],
    "T1543": ["Persistence", "Privilege Escalation"],
    "T1098": ["Persistence", "Privilege Escalation"],
    "T1136": ["Persistence"],
    "T1505": ["Persistence"],
    "T1558": ["Credential Access"],
    "T1003": ["Credential Access"],
    "T1110": ["Credential Access"],
    "T1555": ["Credential Access"],
    "T1528": ["Credential Access"],
    "T1046": ["Discovery"],
    "T1018": ["Discovery"],
    "T1082": ["Discovery"],
    "T1087": ["Discovery"],
    "T1021": ["Lateral Movement"],
    "T1570": ["Lateral Movement"],
    "T1563": ["Lateral Movement"],
    "T1071": ["Command and Control"],
    "T1090": ["Command and Control"],
    "T1105": ["Command and Control"],
    "T1572": ["Command and Control"],
    "T1567": ["Exfiltration"],
    "T1041": ["Exfiltration"],
    "T1048": ["Exfiltration"],
    "T1074": ["Collection"],
    "T1560": ["Collection"],
    "T1530": ["Collection"],
    "T1114": ["Collection"],
    "T1610": ["Execution", "Initial Access"],
    "T1611": ["Privilege Escalation", "Execution"],
    "T1486": ["Impact"],
    "T1490": ["Impact", "Defense Impairment"],
    "T1498": ["Impact"],
    "T1489": ["Impact"],
    "T1657": ["Impact"],
    "T1027": ["Stealth"],
    "T1036": ["Stealth"],
    "T1070": ["Stealth"],
    "T1562": ["Defense Impairment"],
    "T1112": ["Defense Impairment"],
    "T1222": ["Defense Impairment"],
}

TECHNIQUE_ALIASES: dict[str, str] = {
    "KERBEROASTING": "T1558",
    "RANSOMWARE": "T1486",
    "PHISHING": "T1566",
    "SPEARPHISHING": "T1566",
    "LOLBINS": "T1059",
    "DNS-TUNNELING": "T1071",
    "BEC": "T1566",
}

CSF_CATEGORIES: dict[str, str] = {
    "GV.OC": "Organizational Context",
    "GV.RM": "Risk Management Strategy",
    "GV.RR": "Roles, Responsibilities and Authorities",
    "GV.PO": "Policy",
    "GV.OV": "Oversight",
    "GV.SC": "Cybersecurity Supply Chain Risk Management",
    "ID.AM": "Asset Management",
    "ID.RA": "Risk Assessment",
    "ID.IM": "Improvement",
    "PR.AA": "Identity Management, Authentication and Access Control",
    "PR.AT": "Awareness and Training",
    "PR.DS": "Data Security",
    "PR.PS": "Platform Security",
    "PR.IR": "Technology Infrastructure Resilience",
    "DE.CM": "Continuous Monitoring",
    "DE.AE": "Adverse Event Analysis",
    "RS.MA": "Incident Management",
    "RS.AN": "Incident Analysis",
    "RS.CO": "Incident Response Reporting and Communication",
    "RS.MI": "Incident Mitigation",
    "RC.RP": "Incident Recovery Plan Execution",
    "RC.CO": "Incident Recovery Communication",
}

CSF_FUNCTIONS: dict[str, str] = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

D3FEND_TECHNIQUES: dict[str, str] = {
    "D3-NTA": "Network Traffic Analysis",
    "D3-NTF": "Network Traffic Filtering",
    "D3-PSA": "Process Spawn Analysis",
    "D3-PSEP": "Process Termination",
    "D3-EAL": "Executable Allowlisting",
    "D3-FIM": "File Integrity Monitoring",
    "D3-CBAN": "Credential-Based Access Control",
    "D3-AL": "Account Locking",
    "D3-MFA": "Multi-Factor Authentication",
    "D3-DNSC": "DNS Caching",
    "D3-DNSAL": "DNS Allowlisting",
    "D3-IPCT": "IP Traffic Collection",
    "D3-NI": "Network Isolation",
    "D3-EI": "Endpoint Isolation",
    "D3-SICA": "System Image Consistency Analysis",
    "D3-DSDA": "Data Storage Analysis",
    "D3-UA": "User Activity Analysis",
    "D3-RAPA": "Resource Access Pattern Analysis",
    "D3-PM": "Patch Management",
    "D3-IOPR": "I/O Port Restriction",
}

ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0000": "ML Supply Chain Compromise",
    "AML.T0006": "Active Scanning",
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0015": "Evade AI Model",
    "AML.T0020": "Poison Training Data",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0044": "Full AI Model Access",
    "AML.T0047": "AI-Enabled Product or Service",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
}

AI_RMF_FUNCTIONS: dict[str, str] = {
    "GOVERN": "Govern",
    "MAP": "Map",
    "MEASURE": "Measure",
    "MANAGE": "Manage",
}

F3_TACTICS: dict[str, str] = {
    "FA0001": "Positioning",
    "FA0002": "Monetization",
}

F3_TECHNIQUES: dict[str, str] = {
    "F1005": "Business Email Compromise",
    "F1005.003": "Add Beneficiary",
    "F1005.006": "Phishing for Fraud",
    "F1007": "Adversary-in-the-Browser",
    "F1025.003": "Wire Transfer",
    "F1032": "Money Mule Layering",
    "F1047": "Card Cash-Out",
}

# Tactic weights for risk-weighted coverage (impact of an undetected tactic).
TACTIC_RISK_WEIGHT: dict[str, float] = {
    "Reconnaissance": 0.3,
    "Resource Development": 0.35,
    "Initial Access": 0.9,
    "Execution": 0.85,
    "Persistence": 0.8,
    "Privilege Escalation": 0.85,
    "Stealth": 0.75,
    "Defense Impairment": 0.85,
    "Credential Access": 0.9,
    "Discovery": 0.45,
    "Lateral Movement": 0.85,
    "Collection": 0.7,
    "Command and Control": 0.9,
    "Exfiltration": 0.95,
    "Impact": 1.0,
}


# ── Framework mapping ─────────────────────────────────────────────────────

FRAMEWORK_KEYS = ("attack", "csf", "atlas", "d3fend", "ai_rmf", "f3")


@dataclass
class FrameworkMapping:
    """Which frameworks a skill is mapped into, and at which node."""

    attack: list[str] = field(default_factory=list)
    csf: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    d3fend: list[str] = field(default_factory=list)
    ai_rmf: list[str] = field(default_factory=list)
    f3: list[str] = field(default_factory=list)

    def count(self) -> int:
        return sum(len(getattr(self, key)) for key in FRAMEWORK_KEYS)

    def frameworks(self) -> list[str]:
        return [key for key in FRAMEWORK_KEYS if getattr(self, key)]

    def tactics(self) -> list[str]:
        tactics: list[str] = []
        for technique in self.attack:
            for tactic in resolve_tactics(technique):
                if tactic not in tactics:
                    tactics.append(tactic)
        return tactics

    def unknown(self) -> list[str]:
        """Framework identifiers that do not resolve against the tables."""
        problems: list[str] = []
        for technique in self.attack:
            if normalise_technique(technique) not in TECHNIQUE_TACTICS:
                problems.append(f"unknown ATT&CK technique {technique}")
        for category in self.csf:
            if category not in CSF_CATEGORIES:
                problems.append(f"unknown CSF category {category}")
        for technique in self.d3fend:
            if technique not in D3FEND_TECHNIQUES:
                problems.append(f"unknown D3FEND technique {technique}")
        for technique in self.atlas:
            if technique not in ATLAS_TECHNIQUES:
                problems.append(f"unknown ATLAS technique {technique}")
        for function in self.ai_rmf:
            if function not in AI_RMF_FUNCTIONS:
                problems.append(f"unknown AI RMF function {function}")
        for technique in self.f3:
            if technique not in F3_TECHNIQUES and technique not in F3_TACTICS:
                problems.append(f"unknown F3 technique {technique}")
        return problems

    def as_dict(self) -> dict[str, list[str]]:
        return {key: list(getattr(self, key)) for key in FRAMEWORK_KEYS}


def normalise_technique(identifier: str) -> str:
    """Uppercase and strip a sub-technique suffix: t1566.001 -> T1566."""
    raw = (identifier or "").strip().upper()
    raw = TECHNIQUE_ALIASES.get(raw, raw)
    match = re.match(r"^(T\d{4})", raw)
    return match.group(1) if match else raw


def resolve_tactics(identifier: str) -> list[str]:
    if not identifier:
        return []
    upper = identifier.strip().upper()
    if upper in ATTACK_TACTICS:
        return [ATTACK_TACTICS[upper]]
    if upper in TACTIC_ORDER:
        return [upper]
    for tactic in ATTACK_TACTICS.values():
        if tactic.lower() == upper.lower():
            return [tactic]
    return list(TECHNIQUE_TACTICS.get(normalise_technique(identifier), []))


def tactic_id(name: str) -> str:
    for identifier, tactic in ATTACK_TACTICS.items():
        if tactic.lower() == (name or "").lower():
            return identifier
    return ""


def sub_technique_of(identifier: str) -> str:
    match = re.match(r"^(T\d{4}\.\d{3})", (identifier or "").strip().upper())
    return match.group(1) if match else ""


# ── Skills ────────────────────────────────────────────────────────────────

@dataclass
class SecuritySkill:
    """One structured, framework-mapped security skill."""

    skill_id: str
    name: str
    domain: str
    tier: str                        # defensive | offensive | dual-use | governance
    summary: str
    mapping: FrameworkMapping
    workflow: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    requires_authorization: bool = False

    @property
    def tactics(self) -> list[str]:
        return self.mapping.tactics()

    def search_text(self) -> str:
        return " ".join([
            self.skill_id.replace("-", " "), self.name, self.domain, self.summary,
            " ".join(self.workflow), " ".join(self.tools),
            " ".join(self.mapping.attack), " ".join(self.mapping.csf),
        ]).lower()

    def relevance(self, terms: set[str]) -> float:
        if not terms:
            return 0.0
        hay = set(re.findall(r"[a-z0-9]+", self.search_text()))
        overlap = terms & hay
        if not overlap:
            return 0.0
        # Technique identifiers are strong evidence; prose terms are weaker.
        strong = len(overlap & {t.lower() for t in self.mapping.attack})
        return round(len(overlap) / math.sqrt(len(hay) + 1) + 0.35 * strong, 4)

    def as_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill_id,
            "name": self.name,
            "domain": self.domain,
            "tier": self.tier,
            "tactics": self.tactics,
            "frameworks": self.mapping.frameworks(),
            "mapping": self.mapping.as_dict(),
            "requires_authorization": self.requires_authorization,
        }


def _skill(
    skill_id: str, name: str, domain: str, tier: str, summary: str,
    attack: list[str], csf: list[str], workflow: list[str],
    d3fend: list[str] | None = None, atlas: list[str] | None = None,
    ai_rmf: list[str] | None = None, f3: list[str] | None = None,
    tools: list[str] | None = None, evidence: list[str] | None = None,
) -> SecuritySkill:
    return SecuritySkill(
        skill_id=skill_id,
        name=name,
        domain=domain,
        tier=tier,
        summary=summary,
        mapping=FrameworkMapping(
            attack=attack, csf=csf, d3fend=d3fend or [], atlas=atlas or [],
            ai_rmf=ai_rmf or [], f3=f3 or [],
        ),
        workflow=workflow,
        tools=tools or [],
        evidence=evidence or [],
        requires_authorization=tier in ("offensive",) or "emulation" in skill_id,
    )


DEFAULT_SKILLS: list[SecuritySkill] = [
    _skill(
        "analyzing-network-traffic-of-malware", "Analyse network traffic of malware",
        "network", "defensive",
        "Reassemble PCAP flows, extract C2 indicators and map them to ATT&CK.",
        ["T1071", "T1090"], ["DE.CM", "DE.AE"],
        ["carve flows from PCAP", "extract JA3/JA3S and DNS queries",
         "match against threat intel", "map to ATT&CK", "write detections"],
        d3fend=["D3-NTA", "D3-IPCT"], tools=["zeek", "suricata", "tshark"],
        evidence=["pcap sha256", "flow table", "IOC list"],
    ),
    _skill(
        "detecting-business-email-compromise", "Detect business email compromise",
        "email", "defensive",
        "Correlate mailbox rules, impossible travel and payment changes to catch BEC.",
        ["T1566", "T1114"], ["DE.AE", "RS.AN"],
        ["pull mailbox audit log", "look for new forwarding rules",
         "check sign-in anomalies", "trace payment change requests", "contain account"],
        d3fend=["D3-UA", "D3-AL"], f3=["F1005", "F1005.006"],
        tools=["m365 audit log", "sigma"], evidence=["mailbox rule dump", "sign-in log"],
    ),
    _skill(
        "memory-forensics-volatility", "Volatile memory forensics",
        "forensics", "defensive",
        "Extract processes, injected regions and credentials from a memory image.",
        ["T1055", "T1003"], ["RS.AN", "DE.AE"],
        ["acquire image", "build symbol profile", "list processes and modules",
         "scan for injected code", "dump credential material"],
        d3fend=["D3-PSA", "D3-DSDA"], tools=["volatility3", "avml"],
        evidence=["image hash", "plugin output", "timeline"],
    ),
    _skill(
        "kerberoasting-detection", "Kerberoasting detection",
        "identity", "defensive",
        "Spot abnormal SPN ticket requests and RC4 downgrades in domain logs.",
        ["T1558"], ["DE.CM", "DE.AE"],
        ["enable 4769 auditing", "baseline SPN request volume",
         "alert on RC4 encryption type", "hunt service accounts", "rotate keys"],
        d3fend=["D3-CBAN", "D3-UA"], tools=["windows event log", "sigma"],
        evidence=["4769 events", "service account inventory"],
    ),
    _skill(
        "ransomware-response", "Ransomware containment and recovery",
        "incident-response", "defensive",
        "Isolate, preserve, contain and recover from an active ransomware event.",
        ["T1486", "T1490"], ["RS.MA", "RS.MI", "RC.RP"],
        ["triage scope and isolate hosts", "preserve forensic images",
         "identify encryption binary", "restore from verified backups",
         "rotate credentials", "post-incident review"],
        d3fend=["D3-EI", "D3-FIM"], tools=["edr", "backup console"],
        evidence=["encryption note", "affected host list", "restore log"],
    ),
    _skill(
        "phishing-simulation", "Authorized phishing simulation",
        "social-engineering", "offensive",
        "Run a consented phishing campaign and measure click and report rates.",
        ["T1566"], ["PR.AT"],
        ["define consent and scope", "build lure and landing page",
         "send in waves", "measure click/report rate", "debrief participants"],
        tools=["gophish"], evidence=["consent record", "campaign metrics"],
    ),
    _skill(
        "c2-infrastructure-emulation", "C2 infrastructure emulation",
        "red-team", "offensive",
        "Stand up disposable command-and-control infrastructure for an authorized exercise.",
        ["T1071", "T1090"], ["ID.RA"],
        ["register domains in scope", "configure redirectors",
         "test beacon profile", "monitor blue-team detection", "tear down"],
        tools=["cobalt strike", "sliver"], evidence=["scope approval", "beacon log"],
    ),
    _skill(
        "cloud-breach-scoping", "Cloud breach scoping",
        "cloud", "defensive",
        "Trace an identity compromise across cloud control-plane logs.",
        ["T1078", "T1530"], ["RS.AN", "DE.AE"],
        ["collect control-plane logs", "identify first anomalous call",
         "enumerate created principals", "check data access", "revoke sessions"],
        d3fend=["D3-CBAN", "D3-RAPA"], tools=["cloudtrail", "azure activity log"],
        evidence=["api call timeline", "principal diff"],
    ),
    _skill(
        "kubernetes-runtime-security", "Kubernetes runtime security",
        "container", "defensive",
        "Detect container escapes, privileged pods and crypto-mining in a cluster.",
        ["T1610", "T1611"], ["DE.CM", "PR.PS"],
        ["enable audit policy", "baseline syscalls", "alert on privileged mounts",
         "block hostPath writes", "verify admission policy"],
        d3fend=["D3-EAL", "D3-NI"], tools=["falco", "kube-bench"],
        evidence=["audit log", "falco alerts"],
    ),
    _skill(
        "active-directory-hardening", "Active Directory hardening",
        "identity", "defensive",
        "Remove Kerberos and delegation weaknesses from a domain.",
        ["T1558", "T1003.003"], ["PR.AA", "PR.PS"],
        ["audit SPNs and delegation", "enforce AES", "tier admin accounts",
         "remove unconstrained delegation", "monitor DCSync"],
        d3fend=["D3-CBAN", "D3-MFA"], tools=["bloodhound", "pingcastle"],
        evidence=["delegation report", "tiering plan"],
    ),
    _skill(
        "threat-hunting-sigma-rules", "Threat hunting with Sigma rules",
        "threat-intel", "defensive",
        "Convert hypotheses into portable Sigma detections and backtest them.",
        ["T1059", "T1071"], ["DE.CM", "ID.IM"],
        ["write hypothesis", "draft Sigma rule", "convert to backend query",
         "backtest on 30 days", "tune false positives", "publish"],
        tools=["sigma", "sigmac"], evidence=["rule file", "backtest metrics"],
    ),
    _skill(
        "log-source-onboarding", "Log source onboarding",
        "monitoring", "defensive",
        "Bring a new telemetry source into the SIEM with parsers and health checks.",
        ["T1562"], ["DE.CM"],
        ["inventory source", "normalise to schema", "write parser",
         "add health metrics", "document retention"],
        tools=["siem", "vector"], evidence=["parser tests", "ingest dashboard"],
    ),
    _skill(
        "vulnerability-triage", "Vulnerability triage",
        "application", "defensive",
        "Prioritise findings by exploitability, exposure and business context.",
        ["T1190"], ["ID.RA", "RS.MI"],
        ["deduplicate findings", "score with CVSS and EPSS",
         "check internet exposure", "assign remediation SLA", "verify fix"],
        d3fend=["D3-PM"], tools=["nessus", "epss"], evidence=["triage sheet"],
    ),
    _skill(
        "exploit-development", "Authorized exploit development",
        "red-team", "offensive",
        "Build and validate a proof-of-concept exploit inside an approved scope.",
        ["T1203"], ["ID.RA"],
        ["confirm authorization", "reproduce vulnerability",
         "stabilise exploit", "capture evidence", "report to owner"],
        tools=["pwntools", "gdb"], evidence=["authorization record", "PoC log"],
    ),
    _skill(
        "osint-person-of-interest", "OSINT on a person of interest",
        "osint", "dual-use",
        "Collect lawfully available public data and document every source.",
        ["T1593", "T1592"], ["ID.RA"],
        ["define collection questions", "query public sources",
         "corroborate with two sources", "record provenance", "assess confidence"],
        tools=["public web", "registry search"], evidence=["source list", "confidence notes"],
    ),
    _skill(
        "geolocation-of-imagery", "Geolocation of imagery (IMINT)",
        "imint", "dual-use",
        "Place an image on the map using terrain, shadows and cultural features.",
        ["T1592"], ["ID.RA"],
        ["extract metadata", "measure shadows for sun angle",
         "match terrain and skyline", "corroborate with street-level imagery", "record error"],
        tools=["suncalc", "satellite basemaps"], evidence=["feature match list", "error estimate"],
    ),
    _skill(
        "network-signals-analysis", "Network signals analysis (SIGINT)",
        "sigint", "dual-use",
        "Characterise a radio or network emitter from raw captures.",
        ["T1595"], ["ID.RA"],
        ["capture raw signal", "estimate bandwidth and modulation",
         "extract protocol framing", "correlate with known emitters", "report confidence"],
        tools=["gnuradio", "wireshark"], evidence=["capture hash", "protocol notes"],
    ),
    _skill(
        "humint-interview-planning", "HUMINT interview planning",
        "humint", "dual-use",
        "Plan a structured interview that maximises verifiable information.",
        ["T1593"], ["ID.RA"],
        ["define information requirements", "map existing knowledge",
         "prepare open questions", "plan corroboration", "write summary"],
        evidence=["requirement list", "interview notes"],
    ),
    _skill(
        "supply-chain-risk", "Software supply-chain risk review",
        "supply-chain", "defensive",
        "Assess third-party components, build integrity and vendor exposure.",
        ["T1195"], ["GV.SC", "ID.RA"],
        ["build SBOM", "check provenance and signatures",
         "scan transitive dependencies", "review vendor attestations", "track exceptions"],
        d3fend=["D3-SICA"], tools=["syft", "cosign"], evidence=["sbom", "signature report"],
    ),
    _skill(
        "governance-evidence-collection", "Governance evidence collection",
        "governance", "governance",
        "Assemble auditable evidence for a control framework review.",
        [], ["GV.OC", "GV.OV"],
        ["map controls to evidence", "collect artefacts with timestamps",
         "score gaps", "assign owners", "schedule re-review"],
        evidence=["control matrix", "evidence index"],
    ),
    _skill(
        "regulatory-mapping-nist", "Regulatory to NIST CSF mapping",
        "compliance", "governance",
        "Translate a regulation into NIST CSF 2.0 subcategories and owners.",
        [], ["GV.PO", "GV.RR"],
        ["parse obligations", "map to CSF categories",
         "identify overlapping controls", "assign owners", "publish crosswalk"],
        evidence=["crosswalk table"],
    ),
    _skill(
        "incident-response-tabletop", "Incident response tabletop",
        "training", "governance",
        "Run a scenario-driven exercise and capture decision gaps.",
        [], ["RS.CO", "ID.IM"],
        ["choose scenario", "assign roles", "inject events",
         "record decisions", "publish corrective actions"],
        evidence=["exercise notes", "action register"],
    ),
    _skill(
        "malware-static-analysis", "Malware static analysis",
        "malware", "defensive",
        "Characterise a sample without executing it.",
        ["T1027"], ["RS.AN"],
        ["hash and quarantine", "inspect headers and imports",
         "extract strings and config", "identify packer", "write YARA rule"],
        d3fend=["D3-FIM"], tools=["pe-bear", "yara"], evidence=["sample hash", "YARA rule"],
    ),
    _skill(
        "malware-dynamic-sandbox", "Malware dynamic analysis",
        "malware", "defensive",
        "Observe sample behaviour in an instrumented sandbox.",
        ["T1055", "T1071"], ["RS.AN"],
        ["spin isolated VM", "capture process and network telemetry",
         "extract IOCs", "classify behaviour", "update detections"],
        tools=["cuckoo", "cape"], evidence=["behaviour report", "pcap"],
    ),
    _skill(
        "dns-tunneling-detection", "DNS tunnelling detection",
        "network", "defensive",
        "Find exfiltration hidden in DNS query patterns.",
        ["T1071.004", "T1048"], ["DE.CM"],
        ["baseline query entropy", "score label length and volume",
         "cluster by parent domain", "alert and sinkhole", "verify resolver logs"],
        d3fend=["D3-DNSAL", "D3-NTA"], tools=["zeek", "passivedns"],
        evidence=["query stats", "sinkhole log"],
    ),
    _skill(
        "llm-prompt-injection-testing", "LLM prompt-injection testing",
        "ai-security", "defensive",
        "Probe an LLM application for prompt injection and tool abuse.",
        ["T1059"], ["ID.RA", "DE.AE"],
        ["enumerate entry points", "craft injection payloads",
         "test tool-call boundaries", "measure refusal and leakage", "file findings"],
        atlas=["AML.T0051", "AML.T0057"], ai_rmf=["MEASURE", "MANAGE"],
        tools=["garak", "promptfoo"], evidence=["payload set", "leak samples"],
    ),
    _skill(
        "ml-supply-chain-review", "ML supply-chain review",
        "ml-security", "defensive",
        "Verify model provenance, training-data lineage and artefact signatures.",
        ["T1195"], ["GV.SC", "ID.RA"],
        ["inventory models", "verify artifact hashes",
         "trace dataset provenance", "scan for unsafe serialisation", "record approvals"],
        atlas=["AML.T0010", "AML.T0020"], ai_rmf=["GOVERN", "MAP"],
        tools=["model cards", "safetensors"], evidence=["model card", "hash manifest"],
    ),
    _skill(
        "ai-red-team-jailbreak", "Authorized AI red-team (jailbreak)",
        "ai-security", "offensive",
        "Test model guardrails against jailbreak families with consent.",
        [], ["ID.RA"],
        ["agree scope and harm categories", "build jailbreak corpus",
         "run graded evaluation", "score severity", "report with fixes"],
        atlas=["AML.T0054"], ai_rmf=["MEASURE"],
        tools=["evaluation harness"], evidence=["scope agreement", "score table"],
    ),
    _skill(
        "ai-risk-register", "AI risk register",
        "risk", "governance",
        "Maintain an AI risk register mapped to the NIST AI RMF functions.",
        [], ["GV.RM", "ID.RA"],
        ["identify AI systems", "assess harms", "assign owners and tolerances",
         "track mitigations", "review quarterly"],
        atlas=["AML.T0015"], ai_rmf=["GOVERN", "MAP", "MANAGE"],
        evidence=["risk register export"],
    ),
    _skill(
        "deepfake-detection", "Deepfake and synthetic-media detection",
        "fraud", "defensive",
        "Combine metadata, artefact and provenance checks on suspected synthetic media.",
        ["T1036"], ["DE.AE"],
        ["preserve original", "inspect metadata and compression",
         "run artefact detectors", "check content provenance", "document confidence"],
        f3=["FA0001"], tools=["metadata tools", "detectors"], evidence=["detector scores", "provenance check"],
    ),
    _skill(
        "fraud-transaction-monitoring", "Fraud transaction monitoring",
        "fraud", "defensive",
        "Detect account-takeover and payment fraud patterns in transaction data.",
        ["T1657"], ["DE.CM", "DE.AE"],
        ["model normal payment behaviour", "score new beneficiaries",
         "flag velocity anomalies", "queue for analyst review", "feedback labels"],
        f3=["F1005", "F1025.003", "FA0002"], tools=["fraud engine"], evidence=["alert queue", "model metrics"],
    ),
    _skill(
        "sim-swap-investigation", "SIM-swap investigation",
        "crypto-fraud", "defensive",
        "Reconstruct a SIM-swap takeover across carrier and account logs.",
        ["T1657"], ["RS.AN"],
        ["collect carrier change log", "align with account resets",
         "identify device IMEI changes", "trace fund movement", "file reports"],
        f3=["FA0001", "F1005"], evidence=["carrier log", "timeline"],
    ),
    _skill(
        "crypto-wallet-tracing", "Crypto wallet tracing",
        "crypto-fraud", "defensive",
        "Follow on-chain flows from a victim address to cash-out points.",
        ["T1657"], ["RS.AN"],
        ["label victim address", "cluster related addresses",
         "follow hops with timestamps", "identify exchange deposit", "prepare exhibit"],
        f3=["FA0002", "F1032"], tools=["block explorer"], evidence=["address graph", "exhibit"],
    ),
    _skill(
        "zero-trust-policy-design", "Zero-trust policy design",
        "architecture", "governance",
        "Define identity-centric access policy with continuous verification.",
        ["T1078"], ["PR.AA", "PR.IR"],
        ["inventory assets and flows", "classify data", "define policy decision points",
         "enforce least privilege", "measure enforcement coverage"],
        d3fend=["D3-CBAN", "D3-MFA"], evidence=["policy draft", "flow inventory"],
    ),
    _skill(
        "privileged-access-review", "Privileged access review",
        "identity", "defensive",
        "Find and remove standing privilege that attackers can reuse.",
        ["T1078", "T1098"], ["PR.AA"],
        ["list privileged roles", "map to job function",
         "remove standing access", "require JIT elevation", "review quarterly"],
        d3fend=["D3-CBAN", "D3-AL"], evidence=["role inventory", "removal tickets"],
    ),
    _skill(
        "edr-detection-tuning", "EDR detection tuning",
        "endpoint", "defensive",
        "Reduce alert noise without losing coverage of high-risk behaviour.",
        ["T1055", "T1059"], ["DE.CM"],
        ["export alert sample", "label true and false positives",
         "adjust logic and exclusions", "replay 30 days", "document rationale"],
        d3fend=["D3-PSA", "D3-EAL"], tools=["edr console"],
        evidence=["before/after metrics", "exclusion list"],
    ),
    _skill(
        "container-image-scanning", "Container image scanning",
        "container", "defensive",
        "Scan images for vulnerable packages and embedded secrets before deploy.",
        ["T1195"], ["PR.PS", "ID.RA"],
        ["build SBOM per image", "scan OS and language packages",
         "scan layers for secrets", "gate the pipeline", "track exceptions"],
        d3fend=["D3-SICA"], tools=["trivy", "grype"], evidence=["scan report", "gate config"],
    ),
    _skill(
        "wireless-security-assessment", "Wireless security assessment",
        "wireless", "offensive",
        "Assess WLAN configuration and rogue access points under authorization.",
        ["T1595"], ["ID.RA"],
        ["confirm scope and quiet hours", "survey spectrum",
         "capture handshakes on owned SSIDs", "test segmentation", "report gaps"],
        tools=["aircrack-ng", "kismet"], evidence=["scope approval", "survey map"],
    ),
    _skill(
        "ddos-mitigation", "DDoS mitigation",
        "availability", "defensive",
        "Detect and absorb a volumetric or application-layer flood.",
        ["T1498"], ["PR.IR", "RS.MI"],
        ["baseline traffic", "classify flood type", "enable scrubbing",
         "rate-limit at edge", "verify service restoration"],
        d3fend=["D3-NTF", "D3-NI"], tools=["cdn", "scrubber"],
        evidence=["traffic baseline", "mitigation timeline"],
    ),
    _skill(
        "data-loss-prevention", "Data-loss prevention",
        "data", "defensive",
        "Stop sensitive data leaving through sanctioned and unsanctioned channels.",
        ["T1567", "T1048"], ["PR.DS", "DE.CM"],
        ["classify data", "inspect egress channels", "block high-risk transfers",
         "alert on bulk access", "review exceptions"],
        d3fend=["D3-DSDA", "D3-NTF"], evidence=["classification register", "DLP alerts"],
    ),
    _skill(
        "ot-ics-security", "OT/ICS security assessment",
        "ot-ics", "defensive",
        "Assess industrial control networks without disrupting operations.",
        ["T1190", "T1078"], ["PR.PS", "DE.CM"],
        ["map the Purdue model", "inventory controllers",
         "review remote access paths", "passive-monitor protocols", "plan segmentation"],
        tools=["passive OT sensor"], evidence=["asset inventory", "segmentation plan"],
    ),
    _skill(
        "mobile-threat-analysis", "Mobile threat analysis",
        "mobile", "defensive",
        "Analyse a suspicious mobile profile, app or MDM event.",
        ["T1547"], ["DE.AE", "PR.AA"],
        ["preserve device state", "review installed profiles",
         "check app entitlements", "compare against baseline", "contain via MDM"],
        tools=["mdm console", "mobile forensics"], evidence=["profile list", "device log"],
    ),
    _skill(
        "deception-environment-operations", "Deception environment operations",
        "deception", "defensive",
        "Operate honeytokens and canary accounts to catch lateral movement.",
        ["T1021", "T1078"], ["DE.CM", "DE.AE"],
        ["place canary credentials", "deploy honeytokens",
         "alert on any interaction", "trace the actor", "rotate tokens"],
        d3fend=["D3-UA"], tools=["canary tokens"],
        evidence=["canary placement map", "alert log"],
    ),
    _skill(
        "forensics-chain-of-custody", "Forensic chain of custody",
        "forensics", "governance",
        "Preserve evidence with hashes, transfer records and defensible handling.",
        [], ["RS.AN", "GV.RR"],
        ["document seizure", "hash every artefact", "store in tamper-evident archive",
         "record every transfer", "verify hashes at hand-off"],
        evidence=["custody form", "hash manifest"],
    ),
    _skill(
        "third-party-breach-notification", "Third-party breach notification",
        "compliance", "governance",
        "Assess a vendor breach for notification duties and contractual levers.",
        [], ["GV.SC", "RS.CO"],
        ["confirm facts with vendor", "map affected data",
         "check contractual clauses", "start notification clock", "draft communications"],
        evidence=["vendor notice", "data map", "notification draft"],
    ),
    _skill(
        "satellite-remote-sensing", "Satellite remote sensing analysis",
        "geospatial", "dual-use",
        "Detect change at a location from multi-temporal imagery.",
        ["T1592"], ["ID.RA"],
        ["select scenes by date", "correct for atmosphere",
         "compute change index", "attribute change", "record confidence"],
        tools=["rasterio"], evidence=["scene list", "change map"],
    ),
    _skill(
        "physical-security-survey", "Physical security survey",
        "physical-security", "dual-use",
        "Assess perimeter, access control and camera coverage coverage gaps.",
        ["T1200"], ["PR.PS"],
        ["walk the perimeter", "map access control", "test camera coverage",
         "review visitor logs", "report gaps"],
        evidence=["survey photos", "coverage map"],
    ),
]


@dataclass
class SkillMatch:
    """A ranked skill candidate."""

    skill: SecuritySkill
    score: float
    reasons: list[str] = field(default_factory=list)


class SkillCatalog:
    """Searchable, framework-mapped skill library."""

    def __init__(self, skills: list[SecuritySkill] | None = None) -> None:
        self.skills: dict[str, SecuritySkill] = {s.skill_id: s for s in (skills or DEFAULT_SKILLS)}

    def __len__(self) -> int:
        return len(self.skills)

    def get(self, skill_id: str) -> SecuritySkill | None:
        return self.skills.get(skill_id)

    def domains(self) -> dict[str, int]:
        counts = Counter(s.domain for s in self.skills.values())
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def by_domain(self, domain: str) -> list[SecuritySkill]:
        return [s for s in self.skills.values() if s.domain == domain]

    def by_tier(self, tier: str) -> list[SecuritySkill]:
        return [s for s in self.skills.values() if s.tier == tier]

    def by_tactic(self, tactic: str) -> list[SecuritySkill]:
        needle = tactic.lower()
        return [s for s in self.skills.values()
                if any(needle == t.lower() for t in s.tactics)]

    def by_framework(self, framework: str) -> list[SecuritySkill]:
        key = framework.lower()
        if key not in FRAMEWORK_KEYS:
            return []
        return [s for s in self.skills.values() if getattr(s.mapping, key)]

    def covering(self, technique: str) -> list[SecuritySkill]:
        parent = normalise_technique(technique)
        out = []
        for skill in self.skills.values():
            for identifier in skill.mapping.attack:
                if normalise_technique(identifier) == parent:
                    out.append(skill)
                    break
        return out

    def search(self, query: str, limit: int = 5) -> list[SkillMatch]:
        terms = set(re.findall(r"[a-z0-9]+", (query or "").lower()))
        upper = (query or "").upper()
        technique_terms = set(re.findall(r"T\d{4}(?:\.\d{3})?", upper))
        matches: list[SkillMatch] = []
        for skill in self.skills.values():
            score = skill.relevance(terms)
            reasons: list[str] = []
            for identifier in technique_terms:
                if any(normalise_technique(t) == normalise_technique(identifier)
                       for t in skill.mapping.attack):
                    score += 1.5
                    reasons.append(f"covers {identifier}")
            if not score:
                continue
            hits = sorted(terms & set(re.findall(r"[a-z0-9]+", skill.search_text())))
            if hits:
                reasons.append(f"terms: {', '.join(hits[:4])}")
            matches.append(SkillMatch(skill, round(score, 4), reasons))
        matches.sort(key=lambda m: (-m.score, m.skill.skill_id))
        return matches[:limit]

    def coverage_report(self) -> dict[str, Any]:
        mapped = [s for s in self.skills.values() if s.mapping.attack]
        tactics: Counter[str] = Counter()
        frameworks: Counter[str] = Counter()
        for skill in self.skills.values():
            for tactic in skill.tactics:
                tactics[tactic] += 1
            for framework in skill.mapping.frameworks():
                frameworks[framework] += 1
        unmapped = [s.skill_id for s in self.skills.values() if s.mapping.unknown()]
        return {
            "skills": len(self.skills),
            "domains": len(self.domains()),
            "per_domain": self.domains(),
            "attack_mapped": len(mapped),
            "tactics_covered": sorted(tactics),
            "per_tactic": dict(tactics),
            "frameworks": dict(frameworks),
            "offensive": len(self.by_tier("offensive")),
            "requires_authorization": len([s for s in self.skills.values() if s.requires_authorization]),
            "invalid_mappings": unmapped,
        }


# ── Technique analysis ────────────────────────────────────────────────────

@dataclass
class KillChainPosition:
    """Where an observed technique sits in the intrusion lifecycle."""

    technique: str
    parent: str
    sub_technique: str
    tactics: list[str]
    stage: str
    risk_weight: float


class TechniqueResolver:
    """Resolve technique identifiers into tactics and kill-chain positions."""

    def __init__(self, catalog: SkillCatalog | None = None) -> None:
        self.catalog = catalog or SkillCatalog()

    def resolve(self, identifier: str) -> KillChainPosition:
        parent = normalise_technique(identifier)
        tactics = resolve_tactics(identifier)
        stage = min(tactics, key=lambda t: TACTIC_ORDER.get(t, 99)) if tactics else ""
        weight = max((TACTIC_RISK_WEIGHT.get(t, 0.5) for t in tactics), default=0.0)
        return KillChainPosition(
            technique=(identifier or "").strip().upper(),
            parent=parent,
            sub_technique=sub_technique_of(identifier),
            tactics=tactics,
            stage=stage,
            risk_weight=weight,
        )

    def tactics_for(self, techniques: Iterable[str]) -> list[str]:
        found: list[str] = []
        for technique in techniques:
            for tactic in resolve_tactics(technique):
                if tactic not in found:
                    found.append(tactic)
        return sorted(found, key=lambda t: TACTIC_ORDER.get(t, 99))

    def kill_chain(self, techniques: Iterable[str]) -> list[dict[str, Any]]:
        positions = [self.resolve(t) for t in techniques if t]
        positions.sort(key=lambda p: (TACTIC_ORDER.get(p.stage, 99), p.technique))
        return [
            {"technique": p.technique, "tactics": p.tactics, "stage": p.stage,
             "risk_weight": p.risk_weight}
            for p in positions
        ]

    def coverage(self, techniques: Iterable[str]) -> dict[str, Any]:
        """Which observed techniques have at least one mapped skill."""
        rows = []
        for technique in techniques:
            parent = normalise_technique(technique)
            skills = self.catalog.covering(technique)
            rows.append({
                "technique": technique,
                "parent": parent,
                "covered": bool(skills),
                "skills": [s.skill_id for s in skills],
                "tactics": resolve_tactics(technique),
            })
        covered = sum(1 for row in rows if row["covered"])
        return {
            "techniques": rows,
            "covered": covered,
            "total": len(rows),
            "ratio": round(covered / len(rows), 4) if rows else 0.0,
        }

    def unknown(self, techniques: Iterable[str]) -> list[str]:
        return [t for t in techniques if normalise_technique(t) not in TECHNIQUE_TACTICS]


# ── NIST CSF assessment ───────────────────────────────────────────────────

@dataclass
class ControlAssessment:
    """One assessed CSF subcategory."""

    category: str
    maturity: int                 # 0-5
    evidence: list[str] = field(default_factory=list)
    owner: str = ""

    def __post_init__(self) -> None:
        if self.category not in CSF_CATEGORIES:
            raise ValueError(f"unknown CSF category {self.category!r}")
        if not 0 <= self.maturity <= 5:
            raise ValueError("maturity must be between 0 and 5")

    @property
    def function(self) -> str:
        return self.category.split(".")[0]


class NistCsfAssessor:
    """Score a CSF 2.0 posture from assessed categories."""

    MAX_MATURITY = 5

    def __init__(self, assessments: list[ControlAssessment] | None = None) -> None:
        self.assessments: dict[str, ControlAssessment] = {
            a.category: a for a in (assessments or [])
        }

    def assess(self, category: str, maturity: int, evidence: list[str] | None = None,
               owner: str = "") -> ControlAssessment:
        record = ControlAssessment(category=category, maturity=maturity,
                                   evidence=evidence or [], owner=owner)
        self.assessments[category] = record
        return record

    def category_scores(self) -> dict[str, float]:
        return {category: record.maturity / self.MAX_MATURITY
                for category, record in sorted(self.assessments.items())}

    def function_scores(self) -> dict[str, float]:
        buckets: dict[str, list[int]] = defaultdict(list)
        for record in self.assessments.values():
            buckets[record.function].append(record.maturity)
        return {
            function: round((sum(values) / len(values)) / self.MAX_MATURITY, 4)
            for function, values in sorted(buckets.items())
        }

    def overall(self) -> float:
        if not self.assessments:
            return 0.0
        total = sum(record.maturity for record in self.assessments.values())
        return round(total / (len(self.assessments) * self.MAX_MATURITY), 4)

    def coverage(self) -> float:
        """Fraction of the 22 CSF categories that have any assessment."""
        return round(len(self.assessments) / len(CSF_CATEGORIES), 4)

    def gaps(self, target: int = 3) -> list[dict[str, Any]]:
        found = [
            {
                "category": category,
                "name": CSF_CATEGORIES[category],
                "maturity": record.maturity,
                "deficit": max(0, target - record.maturity),
                "owner": record.owner,
                "evidence": len(record.evidence),
            }
            for category, record in self.assessments.items()
            if record.maturity < target
        ]
        found.sort(key=lambda row: (-row["deficit"], row["category"]))
        return found

    def prioritized_actions(self, limit: int = 5) -> list[str]:
        actions = []
        for gap in self.gaps(target=3)[:limit]:
            actions.append(
                f"Raise {gap['category']} ({gap['name']}) from {gap['maturity']} to 3"
            )
        return actions

    def unassessed(self) -> list[str]:
        return [category for category in CSF_CATEGORIES if category not in self.assessments]


# ── Detection coverage ────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    """A deployed detection and the techniques it is meant to catch."""

    rule_id: str
    name: str
    techniques: list[str]
    enabled: bool = True
    fidelity: float = 0.7        # 0..1 — how reliably it fires

    def covers(self, technique: str) -> bool:
        parent = normalise_technique(technique)
        return any(normalise_technique(t) == parent for t in self.techniques)


@dataclass
class CoverageResult:
    """Detection coverage across the kill chain."""

    per_tactic: dict[str, float]
    per_technique: dict[str, float]
    weighted: float
    covered: list[str]
    gaps: list[str]
    rules: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "weighted_coverage": round(self.weighted, 4),
            "per_tactic": {k: round(v, 4) for k, v in self.per_tactic.items()},
            "per_technique": {k: round(v, 4) for k, v in self.per_technique.items()},
            "covered": self.covered,
            "gaps": self.gaps,
            "rules": self.rules,
        }


class DetectionCoverageEngine:
    """Measure and improve detection coverage over a technique set."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = list(rules or [])

    def add(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def _technique_score(self, technique: str) -> float:
        best = 0.0
        for rule in self.rules:
            if rule.enabled and rule.covers(technique):
                best = max(best, min(max(rule.fidelity, 0.0), 1.0))
        return best

    def evaluate(self, techniques: Iterable[str]) -> CoverageResult:
        technique_list = [t for t in techniques if t]
        per_technique = {t: self._technique_score(t) for t in technique_list}

        tactic_buckets: dict[str, list[float]] = defaultdict(list)
        for technique, score in per_technique.items():
            for tactic in resolve_tactics(technique):
                tactic_buckets[tactic].append(score)
        per_tactic = {
            tactic: round(sum(scores) / len(scores), 4)
            for tactic, scores in tactic_buckets.items()
        }

        weighted_num = 0.0
        weighted_den = 0.0
        for technique, score in per_technique.items():
            tactics = resolve_tactics(technique) or [""]
            weight = max(TACTIC_RISK_WEIGHT.get(t, 0.5) for t in tactics)
            weighted_num += score * weight
            weighted_den += weight
        weighted = weighted_num / weighted_den if weighted_den else 0.0

        covered = [t for t, s in per_technique.items() if s > 0]
        gaps = [t for t, s in per_technique.items() if s == 0]
        return CoverageResult(
            per_tactic=per_tactic, per_technique=per_technique,
            weighted=weighted, covered=covered, gaps=gaps, rules=len(self.rules),
        )

    def recommendations(self, techniques: Iterable[str], catalog: SkillCatalog | None = None,
                        limit: int = 5) -> list[dict[str, Any]]:
        catalog = catalog or SkillCatalog()
        result = self.evaluate(techniques)
        scored: list[tuple[float, SecuritySkill, str]] = []
        for technique in result.gaps:
            weight = max(
                (TACTIC_RISK_WEIGHT.get(t, 0.5) for t in resolve_tactics(technique)),
                default=0.5,
            )
            for skill in catalog.covering(technique):
                scored.append((weight, skill, technique))
        scored.sort(key=lambda item: (-item[0], item[1].skill_id))
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for weight, skill, technique in scored:
            if skill.skill_id in seen:
                continue
            seen.add(skill.skill_id)
            out.append({
                "skill": skill.skill_id,
                "name": skill.name,
                "closes": technique,
                "risk_weight": weight,
                "tier": skill.tier,
            })
            if len(out) >= limit:
                break
        return out

    def matrix(self, techniques: Iterable[str]) -> dict[str, dict[str, float]]:
        matrix: dict[str, dict[str, float]] = {}
        for tactic in ATTACK_TACTICS.values():
            row = {}
            for technique in techniques:
                if tactic in resolve_tactics(technique):
                    row[technique] = self._technique_score(technique)
            if row:
                matrix[tactic] = row
        return matrix


# ── Recommendation ────────────────────────────────────────────────────────

class SkillRecommender:
    """Rank skills for an incident from techniques, keywords and domain."""

    def __init__(self, catalog: SkillCatalog | None = None) -> None:
        self.catalog = catalog or SkillCatalog()

    def recommend(
        self, techniques: Iterable[str] = (), keywords: str = "",
        domain: str = "", tier: str = "defensive", limit: int = 5,
    ) -> list[dict[str, Any]]:
        technique_list = [t for t in techniques if t]
        terms = set(re.findall(r"[a-z0-9]+", (keywords or "").lower()))
        if not technique_list and not terms:
            return []
        scores: list[tuple[float, SecuritySkill, dict[str, float]]] = []
        for skill in self.catalog.skills.values():
            breakdown = {"technique": 0.0, "keyword": 0.0, "domain": 0.0, "tier": 0.0}
            for technique in technique_list:
                if any(normalise_technique(t) == normalise_technique(technique)
                       for t in skill.mapping.attack):
                    breakdown["technique"] += 2.0
            if terms:
                breakdown["keyword"] = skill.relevance(terms)
            if domain and skill.domain == domain:
                breakdown["domain"] = 1.0
            if tier and skill.tier == tier:
                breakdown["tier"] = 0.5
            total = sum(breakdown.values())
            if total > 0:
                scores.append((round(total, 4), skill, breakdown))
        scores.sort(key=lambda item: (-item[0], item[1].skill_id))
        return [
            {
                "skill": skill.skill_id,
                "name": skill.name,
                "score": total,
                "breakdown": breakdown,
                "requires_authorization": skill.requires_authorization,
                "tactics": skill.tactics,
            }
            for total, skill, breakdown in scores[:limit]
        ]


# ── Playbooks ─────────────────────────────────────────────────────────────

RESPONSE_PHASES = [
    ("Preparation", "PR"),
    ("Detection & Analysis", "DE"),
    ("Containment", "RS"),
    ("Eradication", "RS"),
    ("Recovery", "RC"),
    ("Lessons Learned", "ID"),
]

PHASE_FOR_TACTIC: dict[str, str] = {
    "Reconnaissance": "Preparation",
    "Resource Development": "Preparation",
    "Initial Access": "Containment",
    "Execution": "Containment",
    "Persistence": "Eradication",
    "Privilege Escalation": "Eradication",
    "Stealth": "Detection & Analysis",
    "Defense Impairment": "Eradication",
    "Credential Access": "Containment",
    "Discovery": "Detection & Analysis",
    "Lateral Movement": "Containment",
    "Collection": "Detection & Analysis",
    "Command and Control": "Containment",
    "Exfiltration": "Containment",
    "Impact": "Recovery",
}


@dataclass
class PlaybookStep:
    """One actionable step in a response playbook."""

    phase: str
    order: int
    skill_id: str
    action: str
    framework_refs: list[str] = field(default_factory=list)
    requires_authorization: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase, "order": self.order, "skill": self.skill_id,
            "action": self.action, "framework_refs": self.framework_refs,
            "requires_authorization": self.requires_authorization,
        }


@dataclass
class Playbook:
    """A composed, framework-crosswalked response playbook."""

    title: str
    severity: str
    steps: list[PlaybookStep] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)

    def by_phase(self) -> dict[str, list[PlaybookStep]]:
        grouped: dict[str, list[PlaybookStep]] = {name: [] for name, _f in RESPONSE_PHASES}
        for step in self.steps:
            grouped.setdefault(step.phase, []).append(step)
        return grouped

    def phase_coverage(self) -> dict[str, int]:
        return {phase: len(steps) for phase, steps in self.by_phase().items()}

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "techniques": self.techniques,
            "phase_coverage": self.phase_coverage(),
            "frameworks": self.frameworks,
            "steps": [s.as_dict() for s in self.steps],
        }

    def render_markdown(self) -> str:
        lines = [f"# {self.title}", "", f"**Severity:** {self.severity}", ""]
        if self.techniques:
            lines.append(f"**Techniques:** {', '.join(self.techniques)}")
            lines.append("")
        for phase, steps in self.by_phase().items():
            if not steps:
                continue
            lines.append(f"## {phase}")
            for step in steps:
                refs = f" _({', '.join(step.framework_refs)})_" if step.framework_refs else ""
                auth = " **[authorization required]**" if step.requires_authorization else ""
                lines.append(f"{step.order}. {step.action}{refs}{auth}")
            lines.append("")
        return "\n".join(lines).strip()


def severity_for(techniques: Iterable[str], assets: int = 1) -> dict[str, Any]:
    """Severity model: max tactic weight, breadth of the chain and asset count."""
    positions = [TechniqueResolver().resolve(t) for t in techniques if t]
    if not positions:
        return {"severity": "low", "score": 0.0, "tactics": [], "techniques": 0}
    peak = max(p.risk_weight for p in positions)
    tactics = {t for p in positions for t in p.tactics}
    breadth = min(1.0, len(tactics) / 6.0)
    spread = min(1.0, len(positions) / 8.0)
    exposure = min(1.0, math.log1p(max(1, assets) - 1) / math.log(10))
    score = round(0.5 * peak + 0.2 * breadth + 0.15 * spread + 0.15 * exposure, 4)
    if score >= 0.8:
        label = "critical"
    elif score >= 0.6:
        label = "high"
    elif score >= 0.4:
        label = "medium"
    else:
        label = "low"
    return {
        "severity": label,
        "score": score,
        "tactics": sorted(tactics, key=lambda t: TACTIC_ORDER.get(t, 99)),
        "techniques": len(positions),
        "peak_tactic_weight": peak,
    }


class PlaybookComposer:
    """Compose a phased response playbook from observed techniques."""

    def __init__(self, catalog: SkillCatalog | None = None) -> None:
        self.catalog = catalog or SkillCatalog()
        self.recommender = SkillRecommender(self.catalog)

    def compose(
        self, title: str, techniques: Iterable[str], assets: int = 1, limit: int = 6,
    ) -> Playbook:
        technique_list = [t for t in techniques if t]
        severity = severity_for(technique_list, assets=assets)
        selected = self.recommender.recommend(
            technique_list, keywords=title, tier="defensive", limit=limit,
        )
        steps: list[PlaybookStep] = []
        counter = 0
        frameworks: dict[str, set[str]] = defaultdict(set)

        def add(phase: str, skill_id: str, action: str, refs: list[str],
                auth: bool = False) -> None:
            nonlocal counter
            counter += 1
            steps.append(PlaybookStep(phase, counter, skill_id, action, refs, auth))
            for ref in refs:
                frameworks[ref.split(":")[0]].add(ref)

        add("Preparation", "incident-scope", "Confirm scope, severity and responders",
            ["CSF:RS.MA", f"ATTACK:{severity['tactics'][0] if severity['tactics'] else 'TA0001'}"])
        add("Detection & Analysis", "technique-triage",
            f"Validate {len(technique_list)} technique(s) against telemetry",
            [f"ATTACK:{normalise_technique(t)}" for t in technique_list][:6])

        for match in selected:
            skill = self.catalog.get(match["skill"])
            if skill is None:
                continue
            phase = self._phase_for_skill(skill)
            action = skill.workflow[0] if skill.workflow else skill.summary
            refs = (
                [f"ATTACK:{normalise_technique(t)}" for t in skill.mapping.attack][:3]
                + [f"CSF:{c}" for c in skill.mapping.csf][:2]
                + [f"D3FEND:{d}" for d in skill.mapping.d3fend][:1]
                + [f"F3:{f}" for f in skill.mapping.f3][:1]
            )
            add(phase, skill.skill_id, action, refs, skill.requires_authorization)
            for step_text in skill.workflow[1:]:
                add(phase, skill.skill_id, step_text, refs)

        add("Eradication", "remove-persistence",
            "Remove persistence, revoke compromised credentials and patch the entry path",
            ["CSF:RS.MI", "D3FEND:D3-CBAN"])
        add("Recovery", "restore-verified-backups",
            "Restore from a verified clean backup and confirm service health",
            ["CSF:RC.RP"])
        add("Lessons Learned", "post-incident-review",
            "Publish findings, detection gaps and corrective actions",
            ["CSF:ID.IM"])

        steps.sort(key=lambda s: (
            [name for name, _f in RESPONSE_PHASES].index(s.phase)
            if s.phase in [name for name, _f in RESPONSE_PHASES] else 99,
            s.order,
        ))
        for index, step in enumerate(steps, start=1):
            step.order = index

        return Playbook(
            title=title,
            severity=severity["severity"],
            steps=steps,
            techniques=technique_list,
            frameworks={key: sorted(values) for key, values in frameworks.items()},
        )

    @staticmethod
    def _phase_for_skill(skill: SecuritySkill) -> str:
        tactics = skill.tactics
        if not tactics:
            return "Eradication" if skill.tier == "defensive" else "Preparation"
        return PHASE_FOR_TACTIC.get(tactics[0], "Detection & Analysis")

    def framework_coverage(self, playbook: Playbook) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for step in playbook.steps:
            for ref in step.framework_refs:
                counts[ref.split(":")[0]] += 1
        return dict(counts)


# ── Rules of engagement ───────────────────────────────────────────────────

@dataclass
class AuthorizationDecision:
    """The outcome of an authorization check."""

    allowed: bool
    reason: str
    skill_id: str = ""
    target: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason,
                "skill": self.skill_id, "target": self.target}


class AuthorizationScope:
    """Rules-of-engagement gate for offensive and dual-use skills.

    Offensive capability is only ever exercised against explicitly authorised
    targets, inside the engagement window, by an approved skill tier.
    """

    def __init__(
        self,
        engagement: str = "",
        authorized_networks: Iterable[str] = (),
        authorized_domains: Iterable[str] = (),
        allowed_tiers: Iterable[str] = (),
        window_start: str = "",
        window_end: str = "",
        approver: str = "",
    ) -> None:
        self.engagement = engagement
        self.networks = [ipaddress.ip_network(net, strict=False) for net in authorized_networks]
        self.domains = [d.lower() for d in authorized_domains]
        self.allowed_tiers = set(allowed_tiers) or {"defensive", "governance"}
        self.window_start = self._parse(window_start)
        self.window_end = self._parse(window_end)
        self.approver = approver
        self.audit: list[dict[str, Any]] = []

    @staticmethod
    def _parse(stamp: str) -> datetime | None:
        if not stamp:
            return None
        try:
            parsed = datetime.fromisoformat(stamp)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def in_window(self, when: datetime | None = None) -> bool:
        moment = when or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        if self.window_start and moment < self.window_start:
            return False
        if self.window_end and moment > self.window_end:
            return False
        return True

    def target_authorized(self, target: str) -> bool:
        if not target:
            return False
        candidate = target.strip().lower()
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            address = None
        if address is not None:
            return any(address in network for network in self.networks)
        if "/" in candidate:                     # a CIDR range must be inside a network
            try:
                requested = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                return False
            return any(
                requested.subnet_of(network) for network in self.networks
                if requested.version == network.version
            )
        host = candidate.split(":")[0]
        for pattern in self.domains:
            if fnmatch.fnmatch(host, pattern) or host == pattern:
                return True
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
        return False

    def check(
        self, skill: SecuritySkill | str, target: str = "",
        when: datetime | None = None,
    ) -> AuthorizationDecision:
        skill_obj = skill if isinstance(skill, SecuritySkill) else None
        skill_id = skill_obj.skill_id if skill_obj else str(skill)
        tier = skill_obj.tier if skill_obj else "offensive"
        aggressive = bool(skill_obj and skill_obj.requires_authorization) or tier == "offensive"

        if not self.engagement:
            decision = AuthorizationDecision(False, "no engagement on record", skill_id, target)
        elif aggressive and tier not in self.allowed_tiers:
            decision = AuthorizationDecision(
                False, f"tier '{tier}' is not approved for this engagement", skill_id, target,
            )
        elif not self.in_window(when):
            decision = AuthorizationDecision(False, "outside the authorized window", skill_id, target)
        elif aggressive and not self.target_authorized(target):
            decision = AuthorizationDecision(
                False, f"target '{target}' is outside the authorized scope", skill_id, target,
            )
        else:
            decision = AuthorizationDecision(
                True, "within scope, window and approved tier", skill_id, target,
            )
        self.audit.append({
            **decision.as_dict(),
            "when": (when or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        })
        return decision

    def report(self) -> dict[str, Any]:
        allowed = sum(1 for row in self.audit if row["allowed"])
        return {
            "engagement": self.engagement,
            "approver": self.approver,
            "checks": len(self.audit),
            "allowed": allowed,
            "denied": len(self.audit) - allowed,
            "networks": [str(n) for n in self.networks],
            "domains": list(self.domains),
            "allowed_tiers": sorted(self.allowed_tiers),
        }


# ── Fraud mapping ─────────────────────────────────────────────────────────

class FraudMapper:
    """Map skills and techniques into the MITRE F3 fraud framework."""

    def __init__(self, catalog: SkillCatalog | None = None) -> None:
        self.catalog = catalog or SkillCatalog()

    def skills_for_technique(self, technique: str) -> list[str]:
        parent = normalise_technique(technique)
        out = []
        for skill in self.catalog.skills.values():
            if any(normalise_technique(t) == parent for t in skill.mapping.attack):
                if skill.mapping.f3:
                    out.append(skill.skill_id)
        return out

    def monetization_path(self, f3_ids: Iterable[str]) -> dict[str, Any]:
        tactics = sorted({F3_TACTICS["FA0002"]} | {
            F3_TACTICS[t] for t in f3_ids if t in F3_TACTICS
        })
        techniques = [
            {"id": identifier, "name": F3_TECHNIQUES.get(identifier, "unknown")}
            for identifier in f3_ids
        ]
        return {
            "tactics": tactics or [F3_TACTICS["FA0002"]],
            "techniques": techniques,
            "known": all(t["name"] != "unknown" for t in techniques),
        }

    def coverage(self) -> dict[str, Any]:
        mapped = [
            skill.skill_id for skill in self.catalog.skills.values() if skill.mapping.f3
        ]
        return {
            "fraud_skills": len(mapped),
            "techniques": {k: F3_TECHNIQUES[k] for k in sorted({
                t for s in self.catalog.skills.values() for t in s.mapping.f3
                if t in F3_TECHNIQUES
            })},
            "skills": sorted(mapped),
        }


# ── Incident report ───────────────────────────────────────────────────────

@dataclass
class IncidentEvent:
    """One observed event in an incident timeline."""

    timestamp: str
    description: str
    technique: str = ""
    host: str = ""
    source: str = ""


class IncidentReport:
    """Build a structured, framework-crosswalked incident report."""

    def __init__(self, title: str, catalog: SkillCatalog | None = None) -> None:
        self.title = title
        self.catalog = catalog or SkillCatalog()
        self.events: list[IncidentEvent] = []
        self.assets: set[str] = set()

    def add_event(self, event: IncidentEvent) -> None:
        self.events.append(event)
        if event.host:
            self.assets.add(event.host)

    def techniques(self) -> list[str]:
        seen: list[str] = []
        for event in self.events:
            if event.technique and event.technique not in seen:
                seen.append(event.technique)
        return seen

    def crosswalk(self) -> dict[str, list[str]]:
        resolver = TechniqueResolver(self.catalog)
        return {
            "tactics": resolver.tactics_for(self.techniques()),
            "csf": sorted({c for t in self.techniques()
                           for s in self.catalog.covering(t)
                           for c in s.mapping.csf}),
            "d3fend": sorted({d for t in self.techniques()
                              for s in self.catalog.covering(t)
                              for d in s.mapping.d3fend}),
            "skills": sorted({s.skill_id for t in self.techniques()
                              for s in self.catalog.covering(t)}),
        }

    def timeline(self) -> list[IncidentEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)

    def severity(self) -> dict[str, Any]:
        return severity_for(self.techniques(), assets=max(1, len(self.assets)))

    def build(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity(),
            "events": [vars(e) for e in self.timeline()],
            "techniques": self.techniques(),
            "assets": sorted(self.assets),
            "crosswalk": self.crosswalk(),
        }

    def render_markdown(self) -> str:
        payload = self.build()
        severity = payload["severity"]
        lines = [
            f"# {self.title}",
            "",
            f"**Severity:** {severity['severity']} ({severity['score']:.2f})",
            f"**Assets:** {', '.join(payload['assets']) or 'none recorded'}",
            "",
            "## Timeline",
            "",
        ]
        for event in self.timeline():
            technique = f" [{event.technique}]" if event.technique else ""
            host = f" on {event.host}" if event.host else ""
            lines.append(f"- `{event.timestamp}` {event.description}{host}{technique}")
        lines += ["", "## ATT&CK tactics", ""]
        lines += [f"- {tactic}" for tactic in payload["crosswalk"]["tactics"]]
        lines += ["", "## Recommended skills", ""]
        lines += [f"- {skill}" for skill in payload["crosswalk"]["skills"]]
        lines += ["", "## CSF coverage", ""]
        lines += [f"- {category}" for category in payload["crosswalk"]["csf"]]
        return "\n".join(lines)


# ── Facade ────────────────────────────────────────────────────────────────

class CyberSkillsEngine:
    """Facade used by Sentinel pipelines."""

    def __init__(self, catalog: SkillCatalog | None = None) -> None:
        self.catalog = catalog or SkillCatalog()
        self.resolver = TechniqueResolver(self.catalog)
        self.recommender = SkillRecommender(self.catalog)
        self.composer = PlaybookComposer(self.catalog)
        self.fraud = FraudMapper(self.catalog)

    def catalog_summary(self) -> dict[str, Any]:
        return self.catalog.coverage_report()

    def select_skills(self, techniques: Iterable[str] = (), keywords: str = "",
                      domain: str = "", tier: str = "", limit: int = 5) -> list[dict[str, Any]]:
        return self.recommender.recommend(
            techniques, keywords=keywords, domain=domain, tier=tier, limit=limit,
        )

    def coverage(self, techniques: Iterable[str],
                 rules: list[DetectionRule] | None = None) -> dict[str, Any]:
        engine = DetectionCoverageEngine(rules or [])
        result = engine.evaluate(techniques)
        return {
            **result.as_dict(),
            "recommendations": engine.recommendations(techniques, self.catalog),
        }

    def playbook(self, title: str, techniques: Iterable[str], assets: int = 1) -> dict[str, Any]:
        book = self.composer.compose(title, techniques, assets=assets)
        return {
            **book.as_dict(),
            "framework_coverage": self.composer.framework_coverage(book),
            "markdown": book.render_markdown(),
        }

    def triage(self, title: str, events: list[IncidentEvent] | list[dict[str, Any]]) -> dict[str, Any]:
        report = IncidentReport(title, self.catalog)
        for raw in events:
            if isinstance(raw, dict):
                report.add_event(IncidentEvent(**raw))
            else:
                report.add_event(raw)
        payload = report.build()
        return {**payload, "markdown": report.render_markdown()}


# Module-level instance
engine = CyberSkillsEngine()
