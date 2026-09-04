# Compatibility note

For consumers pinning wtquic as a dependency (e.g. libmoq's setup
script). The durable revision is the annotated tag below — pin the tag
or its exact commit SHA; both stay fetchable regardless of later
history rewrites on `main`.

**Dependency point: `v0.1.0-preview.2`.**

(Note: the `v0.1.0-preview.2` tag's own copy of this file still names
`preview.1` here — the tag predates this correction and immutable tags
are not republished. This line on `main` supersedes it; the tagged
CONTENT is otherwise exactly the preview.2 dependency point.)

## WebTransport profile selection

wtquic speaks three WebTransport-over-HTTP/3 wire profiles
(`wtq_webtransport_profile_t`):

- `WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT` (0, the default): draft-16 —
  `:protocol = webtransport-h3`, WT_ENABLED (0x2c7cf000) = 1.
- `WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT` (1): the native-H3
  drafts-13/14 dialect — `:protocol = webtransport`, WT_MAX_SESSIONS
  (0x14e9cd29) = 1, no WT flow control. It never emits the drafts-7–12
  codepoint (0xc671706a).
- `WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_02_RFC9297_COMPAT` (2): the
  browser-compatibility profile — `:protocol = webtransport`,
  ENABLE_WEBTRANSPORT (0x2b603742) = 1, carried over **RFC 9297**
  datagrams (H3_DATAGRAM 0x33 = 1). Selected only when the peer sends
  `0x2b603742 == 1` **and** `0x33 == 1`. It requires the draft-02 §6
  CONNECT markers and an Origin, and caps OUTBOUND stream application
  error codes at 0..255 while still decoding the full 32-bit range
  inbound.

**These three are the whole set.** `H3_CURRENT` and
`H3_DRAFT_13_14_COMPAT` do not provide stock-browser compatibility;
`H3_DRAFT_02_RFC9297_COMPAT` does — see the browser note below.

### Configured set vs selected profile

A **client** requests a single profile
(`wtq_connect_config_t.webtransport_profile`); its connect stays a
singleton.

A **server** configures a capability SET per listener,
`wtq_msquic_listener_cfg_t.webtransport_profiles`
(`wtq_webtransport_profile_set_t`, with the
`WTQ_WEBTRANSPORT_PROFILES_*` constants). Every accepted connection
advertises the deterministic union of that set in its control-stream
settings — advertisement, not selection — and then selects exactly ONE
profile from the peer's settings, by explicit newest-first precedence,
before it processes the extended CONNECT.

The CONNECT `:protocol` token then **validates** that selection; it never
chooses it. Several draft generations share the bare `webtransport`
token, so a token cannot identify a generation on its own. A token that
does not match the selected profile is answered with a generic 400 and
the connection stays usable. If the peers share no profile, nothing is
selected, the request gets one generic 400 that discloses no path or
subprotocol policy, and the session simply does not establish: there is
**no fallback and no retry**.

Query the outcome per session with `wtq_session_webtransport_profile()`.
It returns `WTQ_ERR_STATE` until establishment, then `WTQ_OK` with the
selected profile — valid from inside `on_established`, and stable on a
retained handle after the session ends. On any failure the output is left
untouched, so "not selected yet" can never be misread as the
zero-valued current profile.

ABI: the listener set is a versioned tail field. Absent, partial, or zero
derives a one-member set from the older singular
`webtransport_profile`, so **every existing caller keeps exactly its
previous behavior**; a non-zero set is authoritative and the singular
field is then ignored entirely. Unknown bits, or a non-zero set with no
known member, fail `wtq_msquic_listener_start` with
`WTQ_ERR_INVALID_ARG`. Use `wtq_msquic_listener_cfg_init` (frozen v1) or
`_ex(cfg, struct_size)`. A client profile changed after start is
`WTQ_ERR_STATE`.

### Interop evidence

Evidence for the D13/14 compat profile (captured 2026-07-15): proxygen
2026.05.25.00 uses `H3_WT_MAX_SESSIONS = 0x14e9cd29` with no D07
codepoint anywhere in its tree; the picoquic h3zero family (moqx,
pico_wt) sends both 0x14e9cd29 and 0xc671706a and accepts either. No
D13/14 compat interop target uses 0xc671706a instead of 0x14e9cd29, so
one D13/14 compat profile suffices.

### Browser support: `H3_DRAFT_02_RFC9297_COMPAT`

What a peer ACCEPTS and what it EMITS are separate observations, and only
the emitted dialect tells you which generation it speaks.

Stable Chrome and Firefox emit the older **draft-02** signal
`ENABLE_WEBTRANSPORT` (0x2b603742). That is a different generation from
the drafts-7–12 `WEBTRANSPORT_MAX_SESSIONS` (0xc671706a). wtquic emits
`0x2b603742` for `H3_DRAFT_02_RFC9297_COMPAT` and selects on it; it
**never** emits `0xc671706a` and has no profile that selects on it. Do
not read the two as one "browser" dialect.

The legacy datagram codepoint `0xffd277` has an exact contract: it is
**never emitted**; an incoming `0xffd277` may be decoded and observed as
an unknown/ignored setting, and it **never counts as D02 support** — D02
selection requires RFC 9297 `0x33 == 1`.

The profile is draft-02 **signaling** over **RFC 9297 datagrams**, not a
byte-faithful draft-02/-05 stack: no datagram context or registration
machinery is implemented.

Evidence status:

- **Google Chrome 152.0.7977.66 — live interoperability proven** against
  this profile.
- **Firefox 155 — source coherence only.** There is no live
  exact-binary row yet.
- **Safari — no claim.** Any such claim needs a capture of what Safari
  actually emits, which has not been taken.

`H3_CURRENT` and `H3_DRAFT_13_14_COMPAT` behaviour is unchanged, and
there is **no heuristic fallback**: profiles are selected from peer
SETTINGS only, never from the CONNECT token or headers.

Note that the three profiles do **not** share the entire data/error
plane: `H3_DRAFT_02_RFC9297_COMPAT` has a distinct outbound `0..255`
application error range plus marker and Origin policy. Stream preambles,
datagram association, CLOSE and DRAIN remain shared.

### Known conformance gap

`H3_CURRENT` does not implement `RESET_STREAM_AT` (transport parameter
0x1d), which draft-16 §3.1 lists as required for both roles. This is a
pre-existing gap, unchanged by profile negotiation.

## Network.framework backend availability

- Opt-in: `-DWTQ_BUILD_NETWORK=ON`. Apple platforms only; the
  configure fails elsewhere.
- Installed/exported as the optional `network` component:
  `find_package(wtquic CONFIG COMPONENTS network)` → `wtq::network`;
  `wtquic-network.pc` for pkg-config (carries the Network/Security/
  Foundation framework link flags).
- Client-only (no listener). The MsQuic component (`msquic`,
  `wtq::msquic`) is independent; either or both may be installed, and
  each is resolvable without the other.
- Cross-builds for iOS device and simulator are supported (presets
  `ios-device` / `ios-sim`; `scripts/check_ios_slices.sh` proves both
  slices consumable).

## Minimum Apple deployment versions

**macOS 13.0 / iOS 16.0** (QUIC multiplex connection groups). The
backend carries no runtime availability guards; the deployment target
must meet the floor, and the build enforces this when
`CMAKE_OSX_DEPLOYMENT_TARGET` is set below it.

## Doorbell API

`wtq_nw_conn_cfg_t` versioned tail `on_doorbell`/`doorbell_ctx` plus
`wtq_nw_conn_doorbell_ring()`: a PREALLOCATED, coalescing, infallible
wake into the connection's serialization domain from any thread —
unlike `wtq_nw_conn_post()`, which allocates per submission and can
report `WTQ_ERR_NOMEM`. Rings between deliveries collapse into one
invocation; a ring during delivery re-arms exactly one more. Shutdown
boundary: rings racing or following `stop_begin` may be ABSORBED
(`void` return, deliberately); the handler never runs during or after
`on_stopped`, and rings on a retained post-join handle are no-ops. A
consumer that needs accepted-means-delivered semantics should request
a separate result-returning primitive rather than assume it of the
doorbell.

`wtq_nw_conn_doorbell_ring_after()` / `wtq_nw_conn_doorbell_cancel_after()`
schedule that SAME doorbell on a delay from a one-shot
`DISPATCH_SOURCE_TYPE_TIMER` on the connection domain, preallocated at
connection construction — no per-arm wtquic object, no callback closure,
no configured/backend allocator call, no timer thread (no claim is made
about libdispatch's own internals). The delay is measured in host uptime
(`CLOCK_UPTIME_RAW`, the base a default dispatch timer fires against, so a
suspended system does not consume it — deliberately not the sleep-
inclusive `CLOCK_MONOTONIC`). It rings `on_doorbell`; it does not itself
service the session or infer any application deadline. Both calls are
legal only while the caller owns a valid retained handle (NULL is the
documented result/no-op; a released or stale pointer is invalid). There
is exactly ONE delayed slot: a successful arm REPLACES the previous one
(only the latest governs delivery), `cancel_after` clears an
unpromoted arm, and `delay_us == 0` promotes directly into the immediate
doorbell (a deferred domain delivery, never inline). The ordinary
`wtq_nw_conn_doorbell_ring()` neither arms nor cancels the delayed slot.
`ring_after` returns `WTQ_OK` when armed (armed ≠ delivered — the arm may
still be replaced, canceled, coalesced, or absorbed by teardown),
`WTQ_ERR_INVALID_ARG` on a NULL handle, `WTQ_ERR_UNSUPPORTED` when no
doorbell was configured, and `WTQ_ERR_CLOSED` after `stop_begin`; the
scheduled ring, like the immediate one, never runs during or after
`on_stopped`, and `cancel_after` is an idempotent no-op on a
NULL/unconfigured/stopped/post-join handle. Both are callable from any
thread, including the domain.

## Network.framework ready-transition stream drop (measured)

macOS 15's Network.framework QUIC intermittently DROPS a
server-initiated stream that arrives inside a multiplex connection
group's `waiting -> ready` transition — its own log reports
`quic_stream_add_new_flow ... failed to create new stream for received
stream id N`, and when the stream's data was already acked there is no
retransmit, so the loss is permanent. For WebTransport that stream is
typically the server's H3 control stream: the client then never
receives SETTINGS, cannot legally send the extended CONNECT (RFC
9220), and establishment wedges with no observable error.

Two mitigations ship in wtquic:

- **Main-thread group start**: the failure tracks the thread
  `nw_connection_group_start()` runs on; the backend starts the group
  on the process main thread (off-main creators require a serviced
  main dispatch queue — see the header). This removes one trigger but
  does not close the window.
- **Deferred server bootstrap** (the engine-level workaround): a
  wtquic SERVER opens its control/QPACK streams only on the peer's
  first inbound event instead of at handshake-complete. The client
  sends only after its own transport is demonstrably ready, so a
  wtquic server's streams can no longer land inside the client
  transition window. Measured effect: a Swift async-main loopback
  battery went from double-digit failure rates to 0/200.

REMAINING LIMITATION (scoped to the tested versions — macOS 15.7.3
build 24G419 and iOS 26.2 / SDK 26.2; no App-Store-eligible public fix
found there): a wtquic *client* talking to a THIRD-PARTY HTTP/3 server
that bootstraps eagerly (opens its control stream at handshake-complete,
as RFC 9114 §6.2 says endpoints SHOULD — eager servers are common) can
lose that server-initiated stream
to the OS. The framework creates the inbound stream then rejects the
flow — `nw_protocol_instance_add_new_flow ... No listener registered,
cannot accept new flow`, then `quic_stream_add_new_flow ... failed to
create new stream for received stream id 3` — because its inbound
listener is not registered while the connection is already receiving.
The client never sees SETTINGS, cannot send the RFC 9220 extended
CONNECT, and establishment wedges with no observable error.

Every public approach was measured and ruled out on these versions:

- **Main-thread group start** (shipped, above): necessary but not
  sufficient; the window stays open even with the main dispatch queue
  serviced.
- **Group callback queue on / targeted at the main queue**: shifts the
  race's win probability but does not close it. Adoption of the eager
  stream varied widely from run to run against one relay (roughly a
  quarter to two-thirds of attempts) — environment-specific, never
  deterministic, and NOT a reliable fix. Those figures are observations
  under one set of conditions, not a portable success rate.
- **Zero initial peer stream credit at handshake**
  (`nw_quic_set_initial_max_streams_*(options, 0)`, then raise at ready):
  the framework coerces a literal `0` to its default on the wire
  (measured), so the eager server still opens its control stream. The
  runtime raise via `nw_quic_set_local_max_streams_*` does emit
  MAX_STREAMS, but the handshake barrier is unavailable.
- **`nw_listener_create_with_connection()`**: fails with `EINVAL` before
  the connection is started; it succeeds only against an already-
  connected connection, by which point the eager streams are already
  dropped.
- **The iOS/macOS 26 typed `NetworkConnection<QUIC>` API**
  (`inboundStreams` / `openStream`; the API is available on both iOS and
  macOS 26, but this result was measured only on the iOS 26.2 Simulator):
  tested both orderings against an
  eager relay — `inboundStreams` entered before a delayed `start()`, and
  `start()` before `inboundStreams` — to rule out a handler-registration
  artifact. Both delivered zero server-initiated streams (0/8 each, both
  establishing, no errors thrown). Timestamped os_log shows the framework
  creates its inbound listener via `nw_listener_create_with_connection`
  only after the connection is connected — after the eager stream was
  already dropped — regardless of when `inboundStreams` is called. So the
  typed API inherits the same drop and removes even the intermittent
  queue lever above.

Network.framework also exports WebTransport-specific symbols that are
absent from the public headers/Swift interface —
`nw_parameters_create_webtransport_http`, `nw_webtransport_create_options`,
`nw_protocol_options_is_webtransport`, and related — verified present in
the SDK's `Network.tbd` and resolvable via `dlsym` at runtime on the
tested host (macOS 15.7.3). That proves a DISTINCT PRIVATE WebTransport
configuration surface exists inside the framework, separate from the
public multiplex-group client path; it does NOT by itself prove that
surface receives a server's eager control/QPACK streams. Either way these
symbols are SPI, unavailable to App-Store clients, so the public API is
what a shippable client must use.

wtquic cannot fix the peer or the OS. For a reliable client against
eager conformant third-party H3/WebTransport relays on the tested versions,
use a third-party QUIC stack, and always bound establishment with the
owning layer's connect deadline so the wedge surfaces as a clear failure
rather than an indefinite connecting state.

## Network.framework QUIC limitations (measured)

The following behaviors were measured on macOS 15.7.3 with SDK 26.2.
They are implementation observations, not portable ownership or protocol
rules. The backend preserves the limitations instead of fabricating
transport events that Network.framework did not report.

- A locally extracted stream has no native QUIC id before it is started;
  metadata and the id arrive asynchronously at `ready`. Consequently,
  `wtq_stream_id()` may return `WTQ_STREAM_ID_UNKNOWN` until then.
- Network.framework can deliver a stream's `ready` state with the QUIC
  metadata (and so the id) ABSENT inside that callback frame. Measured
  (366 events over 780 loopback-gate iterations): every such ready was
  STALE — it raced the stream's own failure/cancellation, the stream was
  dead by the next serialization-domain turn, and the metadata never
  materialized later. The backend therefore processes a metadata-less
  ready in two stages: notified in the callback, processed one domain
  turn later — a stream found dying then belongs to its failure path
  (the connection stays up; this raced-ready previously killed the whole
  connection), a stream found alive with metadata processes normally
  (late id report, sends, stamped deferred cancels), and a live stream
  STILL without metadata remains the deterministic connection-fatal
  backend invariant. Stamped cancels and the send pump key off the
  processed stage, so an abort in the one-turn window keeps its exact
  application error code.
- `nw_quic_get_stream_type()` has reported a peer-initiated
  unidirectional stream as a datagram flow. The backend classifies inbound
  streams from the QUIC stream-id bits instead.
- A peer's `STOP_SENDING` and its application code have no public receive
  signal. The backend never infers one. Local stream cancellation retires
  blocked sends and supplies the bounded cleanup path.
- **Receive pause arrests application delivery, not transport-level peer
  backpressure.** `wtq_stream_pause_receive()` stops the engine and the
  application from seeing further bytes (the one already-armed receive
  completion is held in the backend and replayed on resume; no new receive
  is armed). It does NOT impose a hard flow-control bound on the peer: the
  public initial-window setters (`nw_quic_set_initial_max_data`,
  `nw_quic_set_initial_max_stream_data_*`) are *initial* values that
  Network.framework auto-tunes upward, and the framework buffers and ACKs
  received data well past them. Measured: with a 64 KiB advertised
  connection window and a paused stream that delivered nothing to the app,
  a ~500 KiB peer response still completed (was fully ACKed) at the
  transport. So a paused wtquic peer is bounded only by Network.framework's
  internal receive buffering, not by the advertised window. This is a
  documented parity exception; no private API is used to close it. The
  distinction is exposed programmatically, not only in prose:
  `wtq_stream_receive_pause_mode()` reports
  `WTQ_RECEIVE_PAUSE_DELIVERY_ONLY` for the Network backend and
  `WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED` for the MsQuic backend, so a
  bounded-memory caller can decide (accept delivery isolation vs.
  reject/close) instead of assuming a guarantee the header does not make.
  MsQuic earns `FLOW_CONTROLLED` through its logical receive-pause:
  `StreamReceiveSetEnabled(FALSE)` alone is asynchronous (a RECEIVE already
  queued behind it still fires), so the backend keeps per-stream pause
  state and arrests a queued data RECEIVE synchronously by accepting zero
  bytes — MsQuic holds those bytes for in-order redelivery on resume and
  extends no receive credit while nothing is consumed, so a paused peer is
  eventually blocked by QUIC flow control. The capability is a driver bit
  (`WTQ_DCAP_RECV_FLOW_CONTROLLED`) each backend must earn; both backends'
  loopback suites assert their advertised mode against the real transport.
- Stamping group metadata and cancelling the group did not put an
  application-level CONNECTION_CLOSE code on the wire; the peer observed
  a transport close with code zero. The backend therefore does not claim
  peer application-close fidelity.
- In a balanced child-process fixture,
  `nw_connection_group_copy_protocol_metadata()` followed by the
  documented release intermittently crashed during framework teardown.
  The mechanism remains unexplained, so the production backend does not
  call that API.

## Trust failure classification (`NW_TRUST`)

Server certificate/trust rejection on the secure path fails fast and
seals a first-causal transport-error record with
`native_domain == WTQ_ERRDOM_NW_TRUST` (a dedicated domain: classify
trust failure by PROVENANCE — this evaluator rejected the chain — not
by an OSStatus allowlist; `native_code` carries the OSStatus, e.g.
errSecNotTrusted). `insecure_skip_verify` remains a test-only bypass.
Pre-ready failures with no local observation (dead port, DNS) remain
invisible on this SDK; the owning layer's connect timeout governs.
