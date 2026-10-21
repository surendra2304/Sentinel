"""MITRE ATT&CK Enterprise Matrix mapping engine."""

from __future__ import annotations

import re
from typing import Any

from sentinel.modules.threat_intel.models import MitreTactic, MitreTechnique

ENTERPRISE_TACTICS: dict[str, MitreTactic] = {
    "TA0001": MitreTactic(id="TA0001", name="Initial Access", description="Vectors used to gain an initial foothold."),
    "TA0002": MitreTactic(id="TA0002", name="Execution", description="Techniques that result in adversary-controlled code running."),
    "TA0003": MitreTactic(id="TA0003", name="Persistence", description="Maintaining access across restarts or changed credentials."),
    "TA0004": MitreTactic(id="TA0004", name="Privilege Escalation", description="Gaining higher-level permissions on a system."),
    "TA0005": MitreTactic(id="TA0005", name="Defense Evasion", description="Avoiding detection throughout their compromise."),
    "TA0006": MitreTactic(id="TA0006", name="Credential Access", description="Stealing credentials like account names and passwords."),
    "TA0007": MitreTactic(id="TA0007", name="Discovery", description="Observing the environment and gaining situational knowledge."),
    "TA0008": MitreTactic(id="TA0008", name="Lateral Movement", description="Accessing and controlling remote systems on a network."),
    "TA0009": MitreTactic(id="TA0009", name="Collection", description="Gathering data of interest to the adversary goals."),
    "TA0011": MitreTactic(id="TA0011", name="Command and Control", description="Communicating with systems under adversary control."),
    "TA0010": MitreTactic(id="TA0010", name="Exfiltration", description="Stealing data from the target network."),
    "TA0040": MitreTactic(id="TA0040", name="Impact", description="Manipulating, interrupting, or destroying systems and data."),
}

KNOWN_TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["TA0001"],
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program.",
        "patterns": [r"cve-\d{4}-\d+", r"sql injection", r"rce", r"remote code execution", r"ssrf", r"buffer overflow", r"xss", r"unauthenticated"],
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ["TA0002"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "patterns": [r"powershell", r"pwsh", r"-encodedcommand", r"iex\s*\(", r"invoke-expression", r"downloadstring"],
    },
    {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactics": ["TA0002"],
        "description": "Adversaries may abuse Unix shells such as bash or sh to execute commands.",
        "patterns": [r"/bin/(?:ba)?sh", r"/bin/zsh", r"curl\s+.*\|\s*sh", r"wget\s+.*\|\s*bash", r"reverse shell", r"nc\s+-e"],
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["TA0001", "TA0003", "TA0004"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "patterns": [r"default credential", r"hardcoded password", r"compromised token", r"valid account", r"stolen api key"],
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactics": ["TA0005"],
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "patterns": [r"base64[_-]decode", r"xor cipher", r"rot13", r"packed executable", r"obfuscated", r"eval\(base64"],
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": ["TA0006"],
        "description": "Adversaries may attempt to dump credentials from the operating system.",
        "patterns": [r"mimikatz", r"lsass", r"/etc/shadow", r"sam dump", r"procdump", r"ntds\.dit", r"pypykatz"],
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["TA0006"],
        "description": "Adversaries may use brute force techniques to attempt access to accounts.",
        "patterns": [r"brute force", r"password spraying", r"credential stuffing", r"hydra", r"failed login spike"],
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["TA0007"],
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "patterns": [r"port scan", r"nmap", r"masscan", r"open port", r"service banner", r"syn scan"],
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactics": ["TA0011"],
        "description": "Adversaries may communicate using application layer web protocols (HTTP/HTTPS).",
        "patterns": [r"c2 beacon", r"command and control", r"cobalt strike", r"reverse http", r"c2 traffic"],
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ["TA0010"],
        "description": "Adversaries may steal data by exfiltrating it over an alternative protocol.",
        "patterns": [r"dns exfiltration", r"icmp tunnel", r"ftp upload", r"cloud bucket exfil", r"data staging"],
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["TA0040"],
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "patterns": [r"ransomware", r"ransom note", r"encrypted files", r"\.locked$", r"ransom demand"],
    },
]


class MitreMapper:
    """Matches text, finding details, and behavioral indicators against MITRE ATT&CK."""

    def __init__(self) -> None:
        self._compiled_patterns: list[tuple[dict[str, Any], list[re.Pattern[str]]]] = []
        for tech in KNOWN_TECHNIQUES:
            compiled = [re.compile(p, re.IGNORECASE) for p in tech["patterns"]]
            self._compiled_patterns.append((tech, compiled))

    def map_text(self, text: str) -> list[MitreTechnique]:
        """Analyze text and return matching MITRE techniques."""
        if not text:
            return []

        results: list[MitreTechnique] = []
        for tech_def, patterns in self._compiled_patterns:
            matches: list[str] = []
            for pat in patterns:
                found = pat.findall(text)
                if found:
                    matches.extend([str(m) for m in found])

            if matches:
                # Calculate confidence based on pattern hit count
                conf = min(0.99, 0.65 + (len(matches) * 0.1))
                results.append(
                    MitreTechnique(
                        id=tech_def["id"],
                        name=tech_def["name"],
                        tactics=list(tech_def["tactics"]),
                        description=tech_def["description"],
                        confidence=round(conf, 2),
                        matched_patterns=list(set(matches[:5])),
                    )
                )
        return results

    def map_finding(
        self,
        title: str,
        description: str,
        related_cves: list[str] | None = None,
    ) -> list[MitreTechnique]:
        """Correlate finding attributes to MITRE techniques."""
        combined_text = f"{title}\n{description}\n" + " ".join(related_cves or [])
        techniques = self.map_text(combined_text)

        # If CVEs are present but T1190 wasn't matched yet, explicitly include it
        if related_cves and not any(t.id == "T1190" for t in techniques):
            techniques.append(
                MitreTechnique(
                    id="T1190",
                    name="Exploit Public-Facing Application",
                    tactics=["TA0001"],
                    description="Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program.",
                    confidence=0.90,
                    matched_patterns=related_cves[:3],
                )
            )

        return techniques

    def get_tactic(self, tactic_id: str) -> MitreTactic | None:
        """Retrieve Tactic metadata by ID."""
        return ENTERPRISE_TACTICS.get(tactic_id.upper())
