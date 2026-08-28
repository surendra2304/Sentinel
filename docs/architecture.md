# SENTINEL Architecture

## Overview

SENTINEL is a modular, governance-first autonomous cybersecurity platform. Its architecture enforces three invariants:
1. **Evidence-First** — no finding is published without a raw cryptographic artifact reference
2. **Governed Autonomy** — every agent action passes through PolicyEngine + ScopeResolver before execution
3. **Model-Agnostic Intelligence** — all AI reasoning flows through IntelligenceProvider; the platform works fully offline

---

## Component Diagram

mermaid
graph TB
    subgraph Interfaces["External Interfaces"]
        CLI["Typer CLI\nsentinel task submit"]
        REST["REST API\nFastAPI :8000"]
        DASH["Web Dashboard\nReact :3000"]
        FRIDAY["FRIDAY\nService-to-service"]
    end

    subgraph Gateway["Task Gateway Layer"]
        TG["TaskGateway\nPOST /tasks"]
        SR["ScopeResolver\nCIDR / domain / URL"]
        PE["PolicyEngine\n6-dimension evaluation"]
    end

    subgraph Orchestration["Orchestration Core"]
        AO["AutonomousOrchestrator"]
        HP["HeuristicPlanner"]
        LP["LLMPlanner"]
        TWM["TaskWorkingMemory"]
    end

    subgraph Modules["Security Modules (10 Domains)"]
        RA["Recon & DNS Agent"]
        NA["Network Agent"]
        WA["Web Security Agent"]
        AA["API Security Agent"]
        DA["Device Agent"]
        CA["Cloud Agent"]
        VA["Vulnerability Agent"]
        TA["Threat Intel Agent"]
        FA["DFIR Agent"]
        SIA["SecurityIntelligenceAgent"]
    end

    subgraph Evidence["Evidence & Findings Layer"]
        ES["EvidenceStore\nSHA-256 artifacts"]
        FE["FindingEngine\ndedup + lifecycle"]
        RE["RiskEngine\nCVSS scoring"]
        AL["AuditLogger\nHMAC chain"]
    end

    subgraph Intelligence["Cross-Domain Intelligence"]
        FCE["FindingCorrelationEngine"]
        APA["AttackPathAnalyzer"]
        REC["RecommendationEngine"]
        RG["ReportGenerator\n4 report types"]
    end

    subgraph IntelLayer["Intelligence Layer (Phase 8)"]
        IR["IntelligenceRouter"]
        HP2["HeuristicProvider"]
        LLP["LLMProvider\nOpenAI-compatible"]
    end

    subgraph SecOps["Security Operations"]
        SCHED["AssessmentScheduler\nAPScheduler"]
        BASE["BaselineEngine\ndiff detection"]
        ALET["AlertEngine\ndedup + routing"]
        DAGG["DashboardAggregator"]
    end

    CLI --> TG
    REST --> TG
    DASH --> REST
    FRIDAY --> REST

    TG --> SR
    TG --> PE
    PE --> AO

    AO --> HP
    AO --> LP
    AO --> TWM
    AO --> Modules

    Modules --> ES
    ES --> FE
    FE --> RE
    Modules --> AL

    FE --> FCE
    FCE --> APA
    APA --> REC
    REC --> RG

    SIA --> IR
    IR --> HP2
    IR --> LLP

    AO --> SCHED
    SCHED --> BASE
    BASE --> ALET
    ALET --> DAGG


---

## Data Flows

### 1. Task Submission Flow

Client → POST /api/v1/tasks
    → ScopeResolver.validate_targets()        # all targets in-scope?
    → PolicyEngine.evaluate()                  # mode, action class, rate limits OK?
    → Task(status=PENDING) persisted
    → AutonomousOrchestrator.run_task(task)
    → HeuristicPlanner/LLMPlanner.generate_plan()
    → per-step: ExecutionEngine.execute(action) → ToolAdapter → raw output
    → EvidenceStore.store(artifact)            # SHA-256 fingerprint, content-addressed
    → FindingEngine.ingest_observation()       # Evidence-First: rejects no-evidence findings
    → IntelligenceRouter [correlation, quality_review, report_synthesis]
    → ReportGenerator.generate_report()
    → Task(status=COMPLETE) + 4 report formats


### 2. Evidence Chain (Finding → Raw Artifact)

SecurityReport.findings[i]
    → finding.evidence_refs[j]                 # e.g. "evi-abc123"
    → EvidenceStore.retrieve("evi-abc123")
    → EvidenceArtifact.sha256_hash             # cryptographic integrity proof
    → EvidenceArtifact.raw_content             # original tool output bytes


### 3. Approval Workflow (Elevated-Impact Actions)

Agent proposes ImpactLevel.HIGH action
    → ExecutionEngine: impact_level > configured threshold?
    → POST /api/v1/approvals (status=PENDING_APPROVAL)
    → SSE stream notifies dashboard operator
    → Operator: POST /api/v1/approvals/{id}/approve (with signature)
    → AuditLogger.log_event(APPROVAL_GRANTED)
    → ExecutionEngine resumes action


---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| In-process module execution | Simplifies testing; subprocess sandbox available for untrusted tools |
| Evidence-First invariant | Prevents noise findings; every finding has a cryptographic anchor |
| PolicyEngine default-deny | Safe by default; capability must be explicitly granted per mode |
| HeuristicProvider default | Platform works fully offline; LLM is an additive capability |
| Typed intelligence contracts | Prevents free-text AI output from entering structured security data |
| HMAC-signed audit trail | Tamper-evident; audit entries can be verified independently |