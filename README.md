# Task 04 — Security Log Investigation

This repository contains my beginner-level investigation of a supplied synthetic authentication log.

## Files
- `investigation_report.md` — findings, detection rules, incident timeline, evidence vs. assumptions, and recommendations.
- `normalized_authentication_logs.csv` — normalized copy of the supplied 12-record dataset.

## Summary
The analysis identified:
- A brute-force indicator: three failed password logins for `stu-117` from one IP within 34 seconds.
- A password-spraying indicator: four accounts targeted from one IP within 12 seconds.
- A later successful login for `stu-311` that merits validation but is not, by itself, proof of compromise.

All timestamps are UTC. The sample uses documentation-only IP ranges and synthetic events; the report does not attribute activity to real people or locations.

## How to review
Open `investigation_report.md` first, then inspect `normalized_authentication_logs.csv` to verify the event evidence.
