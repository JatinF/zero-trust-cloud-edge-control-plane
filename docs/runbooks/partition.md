# Runbook: edge partition

## What you should see

An edge with `SetConnected(false)` returns `edge_offline` from `SyncEdge`. Authorization continues against the last verified policy until `not_after`. A grant revoked in the cloud during the partition still permits on that edge. After `SyncEdge` succeeds, the same call returns `grant_revoked` if the grant was revoked, or `grant_expired` if the 5-minute grant window has passed.

## What not to do

Do not describe the partition as an immediate global revoke. Do not extend the offline window to hide the delay. Do not treat a cache entry as an authorization decision.

## Recovery

1. Restore connectivity.
2. Run sync for that edge. The edge fetches the latest eligible snapshot, verifies it, and activates it.
3. Confirm the desired revision is acknowledged and lower pending revisions are superseded.
4. Read `GET /v1/audit/events` for the revoke and the later deny. Rows that were spooled while the store was down appear only after the store is available again.
