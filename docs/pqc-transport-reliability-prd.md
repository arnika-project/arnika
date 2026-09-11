# Product Requirements Document: PQC Transport Reliability

- **Status:** Draft
- **Scope:** PQC key lifetime, UDP dispatch, peer rate limiting, and clock rollback recovery
- **Related components:** [`config/config.go`](../config/config.go), [`udpserver.go`](../udpserver.go), [`ratelimiter.go`](../ratelimiter.go), [`repositories/pqc-hpke.go`](../repositories/pqc-hpke.go)

## 1. Summary

Arnika carries QKD key identifiers and PQC key-agreement frames over the same
UDP listener. The PQC integration introduced new timing and traffic
relationships that the existing configuration, dispatch path, and rate limiter
do not fully account for.

This change must address four failure modes:

1. `PQC_MAX_KEY_AGE` can become shorter than `PQC_ROUND_INTERVAL`.
2. QKD processing can block the UDP read loop and prevent PQC frames from being
   serviced.
3. Legitimate QKD and multi-frame PQC traffic can exhaust the shared per-IP
   rate limit.
4. A backward wall-clock step can prevent confirmed lower rounds from replacing
   a stale key.

The result must preserve fail-closed behavior, bounded resource use, packet
authentication, key-update ordering, and the existing rule that a fresh key
from a higher round wins over a fresh key from a lower round.

## 2. Background

### 2.1 Key lifetime

`PQC_ROUND_INTERVAL` defaults to `INTERVAL`, while `PQC_MAX_KEY_AGE` defaults to
twice `INTERVAL`. If an operator overrides only `PQC_ROUND_INTERVAL`, the two
values become inconsistent. For example:

```text
INTERVAL=10s
PQC_ROUND_INTERVAL=120s
PQC_MAX_KEY_AGE unset -> 20s
```

A healthy PQC key is then stale for approximately 100 seconds before the next
round. In a mode that requires PQC, a rotation during that period invalidates
the WireGuard tunnel.

### 2.2 UDP head-of-line blocking

Production creates an unbuffered QKD result channel. The UDP read loop sends a
decrypted key identifier to that channel after acknowledging the packet. Its
single consumer performs the KMS request and key-writer operation
synchronously.

If that consumer is still processing a previous identifier, the next channel
send blocks the UDP read loop. PQC packets on the same socket are not processed
until the KMS or key-writer operation completes.

### 2.3 Shared rate-limit budget

The per-IP rate limiter runs before packet dispatch, so QKD and PQC packets
consume the same budget. A successful PQC round contributes three inbound
packets to the responder's listening socket:

```text
2 x public-key fragment
1 x initiator confirmation tag
```

PQC response frames are sent from the responder's listening socket back to the
initiator's ephemeral source port. Rate limiting applies only to inbound reads,
so these outbound replies do not consume the listening-socket budget.

At a five-second QKD and PQC interval, up to twelve scheduled events of each
type can occur during a one-minute window. Roles are deterministic but not
guaranteed to alternate evenly. Startup traffic and protocol retries add
further packets, so the static default of 30 packets per minute can reject
legitimate traffic.

### 2.4 Clock rollback

PQC round numbers are derived from wall time. Publication rejects a round lower
than the currently published round so that peers converge when overlapping
rounds complete in different orders.

After wall time moves backwards across a round boundary, newly confirmed rounds
can remain lower than the published round for the duration of the clock step.
The old key continues aging on the monotonic clock and eventually becomes
stale, but lower rounds still cannot replace it. A running process recovers only
when wall time reaches the previous round again or when the process restarts.

## 3. Goals

- Keep the default PQC key lifetime consistent with the configured PQC round
  cadence.
- Reject configurations that make a PQC key stale during every healthy round.
- Keep the UDP read loop responsive while KMS and key-writer operations are
  slow or unavailable.
- Preserve QKD key-update ordering and avoid silent packet loss.
- Size the default rate limit from active protocol traffic and retry behavior.
- Recover from a backward wall-clock step after the previous key becomes stale.
- Preserve convergence when fresh rounds complete out of order.
- Add deterministic regression coverage for all four failure modes.

## 4. Non-goals

- Changing the HPKE ciphersuite, frame format, or key-confirmation algorithm.
- Moving PQC traffic to a separate port or transport.
- Removing pre-authentication flood protection.
- Aligning every QKD rotation with a PQC publication boundary.
- Solving the existing case where a publication lands between the two peers'
  reads of the current PQC key.
- Supporting peers whose clocks differ beyond the configured timestamp and
  round-acceptance windows.
- Changing the default derivation of `PQC_ROUND_TIMEOUT`.

## 5. Functional Requirements

### FR-1: Derive and validate PQC key age

1. When `PQC_MAX_KEY_AGE` is unset, its effective value MUST be:

   ```text
   2 * PQC_ROUND_INTERVAL
   ```

2. When PQC is enabled, `PQC_MAX_KEY_AGE` MUST be strictly greater than
   `PQC_ROUND_INTERVAL`.
3. Invalid configurations MUST fail during startup before sockets, KMS clients,
   or key writers begin processing.
4. The validation error MUST include both effective durations.
5. The repository constructor MUST enforce the same invariant so callers cannot
   bypass configuration validation.
6. An explicitly configured valid `PQC_MAX_KEY_AGE` MUST remain unchanged.
7. Startup output and configuration documentation MUST show the effective
   relationship to `PQC_ROUND_INTERVAL`.

### FR-2: Decouple QKD work from the UDP read loop

1. The UDP read loop MUST NOT block on:
   - QKD result delivery;
   - a KMS request;
   - PQC key retrieval performed during PSK derivation;
   - a key-writer operation.
2. Accepted QKD key identifiers MUST be passed to a bounded queue serviced by a
   single owned worker.
3. The worker MUST process accepted identifiers in receive order. The
   implementation MUST NOT use concurrent workers that can reorder PSK writes.
4. Enqueue from the UDP read loop MUST be non-blocking.
5. The server MUST send a QKD ACK only after the identifier has been accepted
   into the queue.
6. If the queue is full, the server MUST:
   - keep the UDP read loop running;
   - not send a success ACK;
   - emit a rate-limited warning without logging key material; and
   - let the existing sender retry policy handle delivery.
7. Queue saturation MUST NOT silently discard an acknowledged identifier.
8. The worker and queue MUST have an explicit shutdown path and MUST not leak
   goroutines.
9. The queue capacity MUST be bounded and documented in code. It does not need
   to be externally configurable in this change.

### FR-3: Provide a protocol-aware default rate budget

1. When `RATE_LIMIT` is unset, Arnika MUST derive an effective per-IP limit from:
   - `RATE_WINDOW`;
   - `INTERVAL`;
   - `PQC_ROUND_INTERVAL`;
   - whether PQC is enabled;
   - the number of frames in each inbound protocol message;
   - the QKD and PQC retry limits; and
   - the immediate PQC startup round.
2. The calculation MUST use the maximum legitimate inbound role allocation for
   one peer, not an assumed 50/50 role distribution.
3. The calculation MUST use the scheduler's effective cadence, including its
   whole-second floor for PQC rounds.
4. The derived default MUST admit a complete legitimate retry sequence without
   rate-limiting a frame required to finish that sequence.
5. An explicitly configured `RATE_LIMIT` MUST remain an operator override.
6. If an explicit `RATE_LIMIT` is below the calculated legitimate-traffic
   budget, startup MUST emit a warning containing:
   - the configured value;
   - the calculated value;
   - `RATE_WINDOW`; and
   - the active QKD and PQC intervals.
7. The effective limit MUST be printed in startup configuration output.
8. The limiter MUST remain per source IP and bounded in memory.
9. Invalid or unauthenticated traffic MUST remain subject to pre-authentication
   flood protection. A higher protocol-aware budget MUST NOT create an
   unlimited authenticated or unauthenticated path.
10. Frame counts and retry counts used by the budget calculation MUST come from
    shared protocol constants or helpers so they cannot drift from transport
    behavior.

### FR-4: Recover safely from a backward clock step

1. A lower round MUST NOT replace a non-stale published key.
2. A fully confirmed lower round MAY establish a new publication baseline only
   when:
   - the currently published key is stale according to `PQC_MAX_KEY_AGE`;
   - the frame passed the existing authentication, timestamp, and round-window
     checks; and
   - key confirmation completed successfully.
3. The stale decision MUST use monotonic elapsed time where available. It MUST
   NOT derive key age from the adjusted wall clock.
4. A lower-round reset MUST clear the superseded key with the same locking and
   zeroing guarantees as a normal publication.
5. A lower-round reset MUST emit a warning containing the old round, new round,
   and old key age. It MUST NOT log key material.
6. After a reset, later rounds MUST be compared against the new baseline.
7. Peers whose previous keys become stale at slightly different times MUST
   converge no later than the next successfully confirmed round for which both
   peers are eligible to reset.
8. The current higher-round-wins behavior MUST remain unchanged while the
   published key is fresh.
9. This recovery path MUST NOT weaken the existing frame replay window or allow
   an unconfirmed round to become current.

## 6. Reliability and Security Requirements

- No packet path may create an unbounded number of goroutines.
- All queues and retained packet state must have fixed bounds.
- QKD ACK behavior must reflect durable in-process acceptance, not merely
  successful packet decryption.
- A queue overflow, rate-limit rejection, or stale-key condition must preserve
  the configured mode's existing fail-closed behavior.
- Key identifiers and key material must not be added to new warning messages.
- Existing HMAC verification, timestamp validation, encryption, and directional
  key derivation must remain unchanged.
- Existing key zeroing and `sync.RWMutex` publication guarantees must remain
  intact.

## 7. Observability

The implementation MUST provide actionable logs for:

- a QKD identifier rejected because the bounded queue is full;
- an explicit rate limit below the calculated protocol budget;
- the calculated and effective rate limits at startup;
- a lower-round publication accepted because the previous key was stale; and
- a lower round rejected because the current key is still fresh.

Repeated packet-level warnings MUST be rate-limited to avoid turning malformed
or flood traffic into a logging denial of service.

## 8. Acceptance Criteria

| ID | Scenario | Expected result |
| --- | --- | --- |
| AC-1.1 | `INTERVAL=10s`, `PQC_ROUND_INTERVAL=120s`, `PQC_MAX_KEY_AGE` unset | Effective maximum key age is `240s`. |
| AC-1.2 | PQC enabled with maximum key age equal to or shorter than the round interval | Startup fails with both values in the error. |
| AC-1.3 | Explicit maximum key age greater than the round interval | The explicit value is retained. |
| AC-2.1 | The QKD worker is blocked in a KMS request and a valid PQC frame arrives | The PQC handler receives the frame before the PQC round timeout. |
| AC-2.2 | The QKD queue is full and another key identifier arrives | The UDP loop remains responsive and no ACK is sent for the rejected identifier. |
| AC-2.3 | Multiple identifiers are accepted | They are processed by one worker in receive order. |
| AC-2.4 | Server shutdown occurs while work is queued or active | The worker exits without a goroutine leak or send-on-closed-channel panic. |
| AC-3.1 | Defaults are used with `INTERVAL=5s`, PQC enabled, and `RATE_WINDOW=1m` | Maximum legitimate QKD/PQC traffic, including the declared retry budget and startup round, is not rejected. |
| AC-3.2 | Traffic exceeds the effective limit for one source IP | Excess packets are rejected while other source IPs retain their own budgets. |
| AC-3.3 | PQC is disabled | The calculated default excludes PQC frames. |
| AC-3.4 | An explicit limit is below the calculated budget | Arnika starts with the override and emits the required warning. |
| AC-4.1 | Round 101 is published and fresh, then round 100 completes | Round 101 remains published. |
| AC-4.2 | Round 101 is stale after a simulated clock rollback, then round 90 completes and confirms | Round 90 becomes the new baseline and a warning is emitted. |
| AC-4.3 | Two fresh rounds publish in opposite orders on two peers | Both peers retain the same highest round. |
| AC-4.4 | Both peers move backwards and their old keys become stale at slightly different times | They converge by the next mutually eligible successful round. |
| AC-4.5 | A lower round is malformed, unauthenticated, outside the round window, or fails confirmation | It is never published, even when the current key is stale. |

## 9. Test Requirements

### Unit tests

- Configuration defaulting and validation for independent QKD and PQC
  intervals.
- Repository constructor validation for key age versus round interval.
- Protocol-budget calculation for:
  - PQC enabled and disabled;
  - default and five-second intervals;
  - non-default rate windows;
  - startup traffic; and
  - all declared retries.
- Publication behavior for fresh lower rounds, stale lower rounds, equal rounds,
  and higher rounds.
- Preservation of key zeroing during a stale lower-round reset.

### UDP tests

- Block the QKD worker deliberately, then verify that PQC frames and unrelated
  packet types continue through the read loop.
- Fill the QKD queue and verify that the rejected packet receives no ACK.
- Verify ordered processing and clean shutdown.
- Exercise the derived rate limit with a deterministic maximum legitimate
  packet sequence.

### Integration tests

- Run the existing five-second two-peer scenario with the derived default rate
  limit and assert that no legitimate packet is rate-limited.
- Run a required-PQC mode for multiple healthy rounds with
  `INTERVAL != PQC_ROUND_INTERVAL` and assert that neither peer invalidates the
  tunnel because of key age.
- Simulate a coordinated backward round change and assert that both peers
  recover after the old key becomes stale.
- Retain the existing opposite-publication-order regression test.

## 10. Documentation Requirements

Update the following documentation with the final behavior:

- `README.md`
- `CODEFLOW.md`
- `docs/pqc-hpke.md`

The configuration reference must describe:

- `PQC_MAX_KEY_AGE` as `2 * PQC_ROUND_INTERVAL` by default;
- the strict key-age validation;
- the calculated `RATE_LIMIT` default;
- the effect of an explicit rate-limit override; and
- the bounded QKD queue and ACK behavior.

## 11. Rollout and Compatibility

- Existing valid explicit values for `PQC_MAX_KEY_AGE` and `RATE_LIMIT` remain
  effective.
- A previously accepted configuration with
  `PQC_MAX_KEY_AGE <= PQC_ROUND_INTERVAL` becomes a startup error.
- Deployments that rely on the static rate-limit default will receive a new
  calculated value. Operators can retain a fixed value by setting
  `RATE_LIMIT` explicitly.
- Both peers should be upgraded together because ACK timing and effective rate
  budgets affect the shared transport.
- No wire-format or cryptographic-version migration is required.

## 12. Definition of Done

This work is complete when:

1. All functional and security requirements are implemented.
2. Every acceptance criterion has deterministic automated coverage.
3. The five-second integration scenario completes without legitimate
   rate-limit drops or PQC-required invalidations.
4. Existing authentication, replay, publication-order, and key-zeroing tests
   continue to pass.
5. Configuration and protocol documentation reflect the implemented behavior.
