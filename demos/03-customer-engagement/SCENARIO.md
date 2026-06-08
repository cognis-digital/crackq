# Scenario: Engagement ended but jobs still queued

Client engagement ran for 30 days; jobs are now 60 days old.

## Expected findings

- CQ-JOB-001 × 2 (stale)
- CQ-WL-001 on client-a-2

## Why this matters

Stop computing on terminated engagements. Audit for billing accuracy.
