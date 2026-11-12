-- Not executed. Shown so the unique revision and the outbox write stay in one transaction.
INSERT INTO policy_versions (policy_id, revision, digest, signature, expiry, payload)
VALUES ($1, $2, $3, $4, $5, $6);

INSERT INTO outbox_events (event_id, aggregate_id, event_type, published_at, payload)
VALUES ($7, $1, 'policy.revision.committed', NULL, $3);
