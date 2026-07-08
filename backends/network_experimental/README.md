# Network.framework capability probe (EXPERIMENTAL)

**This is not a backend.** It is a contract probe: a self-checking program that
asks the real Apple runtime whether Network.framework's multiplexed QUIC API
can satisfy `wtq_driver_ops` (`src/engine/wt_driver.h`). Apple-only, opt-in,
default OFF, `EXCLUDE_FROM_ALL`, never installed, never exported, absent from
every package config and from ctest/CI. **No SPI or public API change is
applied.**

It ships with a second experimental component, `raw_peer.c`: a bare MsQuic QUIC
server speaking no HTTP/3 and no WebTransport. Everything the Apple client
*emits* is judged by that peer's observation of the wire.

## The probe fails

Every required observation records **PASS**, **FAIL**, or **UNRESOLVED**, and
the process exits nonzero if anything FAILed, if a **required row is missing or
duplicated**, or if the result table overflowed. The required rows are declared
in one central manifest (`REQUIRED_ROWS`), so a skipped test cannot produce exit
zero. A timeout, a wrong application
code, a wrong stream direction, missing metadata, a peer stream-table overflow,
a duplicate marker, or a teardown that never reached a terminal state are all
failures. **UNRESOLVED** means the question was asked correctly and the runtime
gave no answer; it is reported but does not fail the run.

Every claim below is one of those rows. Nothing here is derived from a sleep:
each peer fact is a bounded `pthread_cond_timedwait`, and each Apple fact is a
bounded `dispatch_semaphore_wait`.

## Why an independent peer

Apple's getters and setters address **opposite directions**:

* `nw_quic_get_stream_application_error` — the code **received from the peer**,
  or `UINT64_MAX` if none has been received.
* `nw_quic_set_stream_application_error` — the code **to send to the peer**
  when the stream is closed.

Same asymmetry for `nw_quic_get_application_error` /
`nw_quic_set_application_error`. A local readback is therefore not a
transmission test, and the probe never uses one as evidence.

## Attribution

Every test stream sends a unique **length-delimited** marker (`"<marker>\n"`)
as its first bytes. `raw_peer` reassembles it across RECEIVE fragments — a
marker split over two events still matches — and reports the exact QUIC stream
id carrying it. Duplicate markers are a hard error. Streams the probe did not
create, notably the client-bidi `0` that Network.framework opens on its own,
carry no marker and cannot be confused with a test stream.

Before any stream is stamped or aborted, the probe waits for that exact NW
connection to reach `ready` **with QUIC metadata**, and requires the native id
to equal the id the peer saw. Missing metadata is a hard failure.

Expected-absence ("no RESET was ever sent") is asserted by waiting for the
exact stream to become **terminal** at the peer and then inspecting its whole
event record — never against an arbitrary time window.

## Build and run

```sh
cmake -B build/nwprobe -DWTQ_BUILD_NW_EXPERIMENTAL=ON -DWTQ_BUILD_MSQUIC=ON
cmake --build build/nwprobe --target wtq_nw_probe
scripts/gen_test_certs.sh build/nwprobe/certs
./build/nwprobe/backends/network_experimental/wtq_nw_probe build/nwprobe/certs
echo $?   # 0 = all required rows passed
```

Expected per-run summary on this environment: `20 passed, 0 failed,
4 unresolved, 0 manifest error(s)` (the four unresolved rows:
`recv-stop:signal`, `inbound:type-vs-idbits`, `ownership:group-metadata`,
`conn-close`).

## Environment

| | |
|---|---|
| macOS | 15.7.3 (build 24G419) |
| Xcode | 26.3 |
| macOS SDK | 26.2 |
| Arch | arm64 |
| Peer | raw MsQuic observer, ALPN `h3`, no H3/WT |

Public Apple and MsQuic APIs only. No private framework symbol is called.

## THE GATING RESULT: stream identity is not synchronous

`open_uni`/`open_bidi` must return an assigned QUIC stream id **synchronously**,
before any bytes are written.

| # | Sample point | QUIC metadata |
|---|---|---|
| A | immediately after `extract_connection`, **before `start`** | **NULL — asserted** (`ready` cannot precede `start`) |
| B | after `set_queue` + `start` | racy — usually NULL, not asserted |
| C | immediately **before** `nw_connection_send` | racy — observed **populated in 2/20 gated runs** (correct id), not asserted |
| D | immediately **after** `nw_connection_send` returns | racy — observed populated, not asserted |
| E | inside the `ready` callback | present (uni `id=2`, bidi `id=4`) |

`id-async:uni` / `id-async:bidi` assert **A only** — the open-time sample,
exactly where the SPI needs an id, and the one point that is
race-free by construction. B, C and D are post-`start` samples taken on the
app thread while `ready` races on the serial queue: `ready` can land after
`start` alone, before any byte is written, so any of them can legitimately
observe the id. They are reported for the record, never asserted. The gating
verdict — no id is available at open — rests on A and is unchanged.

The peer sharpens the result further: a stream Network.framework had not yet
reported as `ready` was already observed at the peer, carrying its marker
bytes. **Id publication lags the stream's real existence on the wire.** The
probe never synthesizes an id.

### Local stream numbering [peer-confirmed]

* Client-initiated **uni**: `2`, `6`, `10`, `14`, …
* First **extracted** client-bidi: `4`, then `8`, `12`, …
* **Network.framework opens client-bidi `0` itself**, never surfacing it as an
  extracted connection. That is why the first bidi an application sees is `4`,
  and it kills any speculative-id scheme.

## Per-stream options

A **fresh** `nw_quic_create_options()` handed to `extract_connection` kills the
stream (`posix/50`), empty or flagged, retained or not: it re-specifies the
whole connection-level QUIC protocol instance. `nil` options yield a stream
that is always bidirectional, so direction cannot be requested. The working
route copies the group's live transport options:

```c
nw_parameters_t p       = nw_connection_group_copy_parameters(group);
nw_protocol_stack_t st  = nw_parameters_copy_default_protocol_stack(p);
nw_protocol_options_t o = nw_protocol_stack_copy_transport_protocol(st);
nw_quic_set_stream_is_unidirectional(o, true);
nw_quic_set_stream_is_datagram(o, false);   /* set EVERY flag, EVERY time */
nw_connection_group_extract_connection(group, NULL, o);
```

`options-alias` records that two successive `copy_transport_protocol()` calls
return **the same pointer**: it is a retain of the group's live options, not a
copy. Mutating one is visible through the other.

`overlap:ids` proves the flags are nevertheless read **synchronously at
extract**. Modelling `wtq_conn_start()` exactly — three unidirectional extracts
back-to-back, then a bidi, then a datagram flow, *all before any is started* —
every id and direction is correct at the peer, and `overlap:dgram` shows the
overlapping datagram flow carries an exact payload in **both** directions.

So a backend must treat **"set every flag + extract" as one indivisible,
serialized operation**. No serialization through `ready` is required.
Concurrent configuration from two threads would race on shared state.

## The half-stream matrix — all peer-observed, all asserted at terminal

`0x1234` = 4660, `0x4321` = 17185. RESET_STREAM (send half) and STOP_SENDING
(receive half) are distinct frames and are never collapsed.

Each row asserts RESET, STOP **and FIN** explicitly, against the stream's
event record once it is terminal at the peer.

| Row | Case | Asserted: RESET / STOP / FIN |
|---|---|---|
| `reset:local-uni` | local uni, stamp + cancel | `4660` / none / **no FIN** (a reset supersedes it; a client-uni has no receive half) |
| `cancel:bidi-stamped` | local bidi, stamp + cancel | `4660` / `4660` / **no FIN** (RESET aborts the send half) |
| `cancel:bidi-plain` | local bidi, plain cancel | none / `0` / **FIN** (send half closes gracefully) |
| `stop:inbound-uni` | inbound server-uni, stamp + cancel | none / `4660` / **no FIN** (client has no send half) |
| `recv-reset:visible` | peer sends `RESET 0x4321` | getter reports `17185` — **visible** |
| `recv-stop:signal` | peer sends `STOP 0x4321` | **UNRESOLVED** — see below |

So: **`reset_stream` with a chosen application code works**, and **a chosen-code
STOP_SENDING is expressible** by stamping the error and cancelling a stream
that has a receive half. `cancel` is the only teardown verb, so on a bidi the
two frames cannot be issued independently — stamping and cancelling emits both,
with the same code.

### Receiving a STOP_SENDING: UNRESOLVED, not merely "getter absent"

STOP_SENDING targets our **local send half**, so the receive-side getter is
only one of three candidate signals. All three were captured:

* the receive-side getter returns `UINT64_MAX` (nothing received);
* **no terminal state callback** arrives;
* a send issued *after* the STOP does not complete **while the stream stays
  open** — its completion block does not fire within 5 s. It is NOT lost:
  the `send-retirement` fixture below shows that cancelling the stream
  flushes it, exactly once, with `posix/89` (ECANCELED).

No public signal was found that exposes the peer's STOP_SENDING or its code.
Recorded as UNRESOLVED because the absence of a completion callback is itself
an odd result, not a clean "unsupported".

## Send retirement after peer STOP (`send-retirement`)

A dedicated fixture (fresh connection and raw peer) answers when a backend
may free a send record whose completion Network.framework is withholding.
It separates completion **invocation** from completion-block **disposal**
(an ARC-captured sentinel in `send_sentinel.m` — the probe's only
Objective-C — reports disposal from its dealloc; disposal is never inferred
from absence of invocation). Every candidate send is tracked until its block
is disposed; the audit asserts at-most-once invocation, exactly-once
disposal, exactly-once free, and an undisposed candidate makes the row
non-PASS and pins the fixture's roots.

Measured across 20 gated runs — the invariant verdicts below were identical
in every run; only the raced-through count varied:

* **0–3 post-STOP sends race through** (the count varies run to run; the
  STOP's arrival is locally unobservable) and complete exactly once with no
  error before suppression begins; the next send's completion then stays
  pending.
* **`nw_connection_cancel` on the stream flushes the pending completion
  exactly once, with `posix/89` ECANCELED**, at the stream-cancel stage —
  group cancel/terminal were never needed.
* **Disposal occurs on that same cancel path**; normally-completed sends
  dispose promptly at invocation. No double invocation, no double disposal,
  no undisposed candidate in any run.

Consequence for a production backend: a send record is freeable once its
completion has been invoked (or its block provably disposed); cancelling the
stream forces that determinately. Quiescence inference is not needed on the
measured path and is not claimed.

## Datagrams

`dgram:both-ways` requires the **exact payload** to cross in both directions
(`dgram-c2s`, `dgram-s2c`); the peer's send waits for a terminal
`DATAGRAM_SEND_STATE_CHANGED` and frees its context exactly once. Each datagram
must be sent with `is_complete: true`, else `posix/45` (ENOTSUP).

`dgram:usable-size` reports `nw_quic_get_stream_usable_datagram_frame_size()` =
`1439` on the live flow. That is the **current usable size**, *not* the
configured `max_datagram_frame_size` transport parameter.

## Connection application close: UNRESOLVED

`conn-close` runs on a **fresh raw peer and a fresh NW connection group**, with
no streams opened and nothing aborted. It stamps
`nw_quic_set_application_error(group_md, 0x105, "probe close")` and cancels the
group. Across every run the peer observes a **transport** CONNECTION_CLOSE with
code `0` — never an application close, never `0x105`.

No public route to emit a QUIC application-level CONNECTION_CLOSE was found.

## `nw_quic_get_stream_type` cannot classify inbound streams

`inbound:type-vs-idbits` is UNRESOLVED by construction: it PASSes only if the
accessor is ever correct. SDK 26.2 defines `1=bidirectional, 2=unidirectional,
3=datagram`, and `nw_protocol_metadata_is_quic()` is true — yet a
**peer-initiated unidirectional stream reports `nw_type=3` (datagram)**,
colliding with what a real datagram flow reports. It is correct for locally
opened streams. **Use the stream-id bits**, which are authoritative
(RFC 9000 §2.1).

## Detach

wtquic's `detach` is an identity-checked `ds->ectx = NULL` unlink. **It maps
onto no Network.framework call.** A backend keeps its handlers installed for
its own cleanup and send completions, and identity-checks `ds->ectx` before
delivering anything to the engine — exactly as the MsQuic backend does. Detach
neither cancels the stream nor removes a handler.

`detach:no-cancel` supports this: after clearing the state-changed handler, a
send still completes with no error, so clearing handlers does not cancel a
stream. The probe does **not** claim that clearing a handler *suppresses* later
callbacks — with a NULL handler, "zero callbacks" is true by construction.

## Group-metadata ownership: what the experiment actually proves

`nw_connection_group_copy_protocol_metadata()` documents *"Returns a retained
protocol metadata object"* and follows the `copy` naming rule. Unlike
`nw_connection_copy_protocol_metadata()`, it carries no `NW_RETURNS_RETAINED`
annotation — but **a missing annotation proves nothing about runtime
ownership**, so the question is settled by a child-process experiment
(`ownership:group-metadata`).

Each child builds the full rigorous fixture — including **adopting every
hidden inbound connection** (the client-bidi `0` Network.framework opens
itself), then cancelling it, waiting for its terminal state, unhooking and
releasing it — so the four modes differ **only** in the metadata operation.
An earlier draft left those hidden connections retained-but-never-released,
which contaminated the very destruction path the experiment observes; the
counts below are from the corrected, balanced fixture. Children report
distinct exit codes (clean / setup-unavailable / assertion / teardown
failure), and only genuine setup unavailability may become UNRESOLVED —
a teardown, assertion or exec failure fails the whole run.

Four modes, identical except for one step, each run **5 times per probe run**
because the behaviour is intermittent:

| Mode | Step | Crashes (optimized, 20 gated runs) | Crashes (ASan, 1 run) |
|---|---|---|---|
| 0 | baseline, no metadata copy | 0/100 | 0/5 |
| 1 | copy, do not release | 0/100 | 0/5 |
| 2 | copy, **release once** (the documented contract) | **2/5 – 5/5 per run, never 0 in any of 20 runs** | **3/5 – 5/5** |
| 3 | copy, `nw_retain` + `nw_release` (balanced) | 0/100 | 0/5 |

The crash is a SIGSEGV inside `-[NWConcrete_nw_connection dealloc]`'s own
`os_log`, during the group's destruction.

**What this establishes:** releasing this object per its documented contract
triggers an **intermittent crash in Network.framework's own teardown** on
macOS 15.7.3 / SDK 26.2. With the balanced fixture, across 20 gated runs the
per-run rate ranged from 2/5 to 5/5 and was never 0; it does not vanish under
a sanitizer. Modes 0, 1 and 3 never crashed — 0 crashes in 100 optimized reps
each. The crash is attributable to the release itself, not to an unbalanced
hidden connection.

**What this does NOT establish** — two earlier drafts of this document each
overclaimed here, in opposite directions:

* It is **not** proof that the object is `+0`. The rate is not deterministic,
  which is not what a plain over-release looks like.
* It is **not** proof of a mere timing race either. A single ASan sample once
  looked clean; with repetition ASan crashes too (3/5–5/5 across the
  corrected-fixture runs). That earlier "disappears under a sanitizer" claim
  was a one-sample artifact and is withdrawn.
* It is **not** a portable ownership rule. Other OS versions are untested.
* The missing `NW_RETURNS_RETAINED` annotation is **not** evidence of anything.

The honest summary: **`nw_connection_group_copy_protocol_metadata()` + release
is unsafe on this OS, by an unexplained mechanism.**

**Consequences, stated plainly:**

* The probe does not release that object, so **the close path leaks it**. The
  probe therefore makes **no leak-free claim for group-level QUIC metadata**.
* This API is **kept out of the production backend design** until the behaviour
  is understood or resolved with Apple. It is the only public route to a
  connection-level application error, which is one reason `conn-close` remains
  unresolved.

## Other lifecycle bugs found

* A pending `nw_connection_receive()` block and the state-changed handler both
  capture the connection by **raw pointer**. Releasing while either is still
  scheduled frees it underneath them. Correct rundown is `cancel` → **wait for
  the terminal callback** → clear handlers → `nw_release` → free the probe.
  Every `stream_probe` is **heap-owned** for exactly this reason: a stack probe
  whose function returns on a timeout path would leave a live callback writing
  into expired stack memory.
* On teardown timeout the probe **quarantines** the connection *and* its probe:
  it records a FAIL, releases nothing and frees nothing. Releasing a
  possibly-live object is the very UAF the rundown exists to prevent, so that
  leak is deliberate, explicit, and fails the run.
* `gone` is a one-shot semaphore that the RESET/STOP visibility tests may
  already have consumed. Terminal state is therefore tracked by an atomic flag,
  and `shutdown_connection()` only waits when the flag is unset. Waiting twice
  on a consumed one-shot would hang the moment Apple starts surfacing STOP as a
  terminal state.
* Inbound probes are registered **in the new-connection handler, before start**,
  and re-keyed by native stream id at `ready`. Before any registry snapshot,
  the fixture **stops accepting deterministically**: it clears the group's
  new-connection handler and then runs a barrier block through the group's
  serial queue, so an already-scheduled handler invocation cannot register
  after an empty-looking snapshot. Both fixtures (main and isolated close) use
  this.
* **Quarantine root safety:** after the group is cancelled, quarantined
  connections get one more bounded chance to reach a terminal state and are
  released if they do. If any remains live, the run FAILs and the shared roots
  (group, queues, semaphores) are deliberately **not** released — a live
  connection still schedules callbacks against them, and releasing them would
  be the very late-callback UAF the quarantine exists to prevent.
* MsQuic's configuration is a child of the registration and must be closed
  **before** it; `RegistrationClose` then `ConfigurationClose` is a
  use-after-free.
* `raw_peer_stop()` shuts the connection down, **waits (bounded) for its
  `SHUTDOWN_COMPLETE`**, and only then closes each `HQUIC` exactly once, then
  the connection, configuration and registration in that required order. It
  returns false if the connection never quiesced, and that failure reaches the
  verdict accumulator. No callback ever closes a stream handle, which is what
  removes the lookup-then-use race.
* `nw_parameters_create()` + `prepend_application_protocol(quic)` silently
  yields parameters that never start. QUIC is a *transport*:
  `nw_parameters_create_quic()`.

## Where the engine and public API use a stream id

1. **CONNECT stream id → `session_id`.** `conn.c` sets
   `conn->session_id = es->id` and derives the datagram quarter-stream-id
   prefix from `session_id / 4`. Needed before any datagram is sent or matched.
2. **Critical (H3 control/QPACK) stream ids are ignored** by the engine — but
   `wtq_conn_start()` opens those three back-to-back, which is why the
   options-aliasing result had to be settled.
3. **Local WT stream id → the estream**, and it is copied into the public
   `wtq_stream_t` handle (`st->id = id`) **before `wtq_session_open_uni()` /
   `wtq_session_open_bidi()` return**. `wtq_stream_id()` reads that snapshot.
4. **The WT preamble on a locally opened stream carries `conn->session_id`, not
   that stream's own id.** Deferring a local stream's own id would not break
   the preamble.

The incompatibility is with **synchronous public open/query semantics**. An
asynchronous engine-side callback alone does not resolve it:
`wtq_session_open_*()` returns a handle whose `wtq_stream_id()` a caller may
read immediately.

## Candidate SPI changes — **NONE APPLIED**

1. **Deferred id + readiness callback.** `open_*` returns only the backend
   handle; the backend calls `wtq_conn_on_stream_opened(conn, ectx, id)` at
   `ready`. `wtq_stream_id()` must then return a sentinel until the id lands,
   and the public API grows a stream-ready event. Session establishment must
   gate on the CONNECT stream's id, since it becomes `session_id` and the
   datagram association. The three critical streams would each be pending at
   once; the engine ignores their ids, so that is tolerable.
2. **Delay publication of the public handle.** `wtq_session_open_*()` returns
   `WTQ_ERR_WOULD_BLOCK`; the `wtq_stream_t` arrives later as an event. Keeps
   `wtq_stream_id()` total. Larger API break, arguably the most honest model.
3. **Blocking open.** Rejected: blocks a callback thread and deadlocks the
   single serial queue this design depends on.
4. **Speculative id + verification** (MsQuic's `type + (count << 2)`). Not
   viable: NW exposes no counter and opens client-bidi `0` behind your back.
5. **`stop_sending` as an optional op.** Sending works; *receiving* a peer's
   STOP_SENDING surfaces no public signal, and RESET/STOP cannot be issued
   independently on a bidi. The contract must say what a backend may fold.
6. **`send_gather` over a backend-opaque buffer object** so `dispatch_data_t`
   composites carry the zero-copy promise. Possibly unnecessary —
   `dispatch_data_create_concat` is already zero-copy.
7. **Nothing for backpressure. Nothing for detach.**

A transport-error namespace should be designed against *both*
`nw_error_domain_*` and MsQuic's `QUIC_STATUS`, once the above settles.

## Remaining blockers

1. **Asynchronous id publication** vs. synchronous `wtq_session_open_*()` /
   `wtq_stream_id()`. The one that forces a public API change.
2. **A peer's STOP_SENDING surfaces no public signal** (not even a send
   completion), and RESET/STOP cannot be emitted independently on a bidi.
3. **Connection close with an application code never reaches the wire.**
4. `nw_quic_get_stream_type` cannot classify inbound streams.

## Verification

* **20 consecutive runs gated on process exit status**, each producing the
  exact required row manifest.
* `serialization` **asserts** `max_concurrent == 1`; it is not an unconditional
  PASS.
* **ASan**: the parent is clean and exits 0. ASan additionally reports the
  crashes of the ownership experiment's mode-2 children (3/5–5/5 across the
  post-correction runs), which are the experiment's subject, not a defect in
  probe code. `detect_leaks=1` is unavailable on macOS (no LSan in Apple's
  runtime), so leak checking is not claimed.
* **TSan** clean — 0 warnings. Scope: MsQuic and Network.framework are
  uninstrumented prebuilt binaries, so TSan covers `nw_probe.c` and
  `raw_peer.c`, which is the code this pass synchronized.
* Normal teardown and process exit; no `_exit()` in the parent. No callback can
  reference stack memory: every probe is heap-owned, and timeout paths
  quarantine rather than free.
* **Known deliberate leaks, both reported:** the group-level QUIC metadata
  object (see above), and anything quarantined by a teardown timeout (which
  also fails the run).
* Default wtquic build and **38/38** tests unchanged; probe absent from the
  default targets and from `ctest -N`; no `install()`/`export()`/`add_test()`.
