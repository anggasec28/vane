---
name: finding-governance
description: Govern findings through evidence and independent review.
version: 0.2.0
metadata:
  hermes:
    tags: [security, findings, triage]
    category: security
---
# Finding Governance

## When to Use
Use when creating, triaging, validating, disputing, or closing a security finding.

## Procedure
1. Write a concise title, affected asset, observed behavior, impact, and reproducible conditions.
2. Link every material claim to one or more evidence IDs.
3. Separate observation, inference, confidence, root cause, and impact.
4. Check that evidence references exist and are neither disputed nor insufficient.
5. Keep finding status separate from evidence status and mission status.
6. Record remediation and residual risk without changing the original evidence.

## Engine Tool

Use `vane_validate_finding` with the finding JSON and its evidence records before marking a finding VALIDATED.

## Persistence Tools
Use `vane_save_finding` to persist a draft or evidence-validated finding and `vane_list_findings` to review project findings. VALIDATED/ACCEPTED records must resolve to valid, same-project evidence.

## Pitfalls
- Do not promote an unverified hypothesis to a confirmed finding.
- Do not infer severity from a scanner label alone.
- Do not close a finding solely because remediation was proposed.

## Verification
A validated finding has complete evidence links, affected assets, confidence rationale, and a reviewable remediation statement.
