# Runbook: grant expiry and revocation

## Issue

`SYN-USER-JULES` requests `admin` on `SYN-DB-LEDGER`. `SYN-USER-KIRAN` approves. The grant expiry is the lab clock plus the configured TTL, which is 300 seconds. The approver cannot approve their own request. A second approve of a request that is no longer pending is a conflict.

## Enforcement

Before expiry, the branch edge returns `grant_permit` for that action. A database read without the privileged path stays denied. After the clock passes expiry, the reason is `grant_expired`. If a newer valid grant exists, it wins. If none is valid and any matching grant is expired, the reason is `grant_expired` even when another matching grant was revoked. That order does not depend on map iteration.

## Revoke

An approver or a policy administrator can revoke. Connected edges receive the updated grant snapshot immediately. A disconnected edge does not, until it reconnects or the grant expires on its own clock. Online identity revocation uses the store. The edge does not fall back to a cached allow when the store rejects the token.

## Audit

The request, the approval, the revoke, and the later deny are audit decisions. Confirm `unauthorized_grants` stays 0 on the demo report. No price is applied.
