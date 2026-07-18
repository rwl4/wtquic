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

Both peers pick one WebTransport-over-HTTP/3 wire profile
(`wtq_webtransport_profile_t`), latched before any control-stream
SETTINGS are emitted. A client selects per connection
(`wtq_connect_config_t.webtransport_profile`); a server selects per
listener, connection-wide
(`wtq_msquic_listener_cfg_t.webtransport_profile`) — one profile for
every connection that listener accepts, never auto-negotiated:

- `WTQ_WEBTRANSPORT_PROFILE_H3_CURRENT` (0, the default): draft-16 —
  `:protocol = webtransport-h3`, WT_ENABLED = 1.
- `WTQ_WEBTRANSPORT_PROFILE_H3_DRAFT_13_14_COMPAT` (1, opt-in): the
  native-H3 drafts-13/14 dialect — `:protocol = webtransport`,
  WT_MAX_SESSIONS (0x14e9cd29) = 1, no WT flow control. It never
  advertises the current settings and never emits the drafts-7–12
  codepoint (0xc671706a).

The server is symmetric with the client: it emits its profile's SETTINGS
before it processes any request, and admits ONLY that profile's CONNECT
`:protocol` token (current → `webtransport-h3`, compat → bare
`webtransport`). A cross-profile token is answered with a generic 400;
the server never emits one profile's SETTINGS while honouring the other's
token. So a wtquic compat client and a wtquic compat listener loopback
is self-consistent — the server is not stuck current-only.

ABI: on both the client connect-config and the listener config the
profile is a versioned tail field; a config from an older caller
(smaller `struct_size`) reads as `H3_CURRENT`. Use
`wtq_connect_config_init` / `wtq_msquic_listener_cfg_init` (frozen v1) or
the `_ex(cfg, struct_size)` forms. An out-of-range value is rejected
(`WTQ_ERR_INVALID_ARG`) — at connect for a client, at
`wtq_msquic_listener_start` for a listener; a compat profile requested
after the client already started is `WTQ_ERR_STATE`.

Evidence for the single compat profile (captured 2026-07-15): proxygen
2026.05.25.00 uses `H3_WT_MAX_SESSIONS = 0x14e9cd29` with no D07
codepoint anywhere in its tree; the picoquic h3zero family (moqx,
pico_wt) sends both 0x14e9cd29 and 0xc671706a and accepts either. No
D13/14 compat interop target uses 0xc671706a instead of 0x14e9cd29, so
one D13/14 compat profile suffices.

imquic is NOT a current-profile (draft-16) peer: HEAD 99fa77d sends
`:protocol = webtransport` with `ENABLE_WEBTRANSPORT` (0x2b603742) and
`WEBTRANSPORT_MAX_SESSIONS` (0xc671706a) and `sec-webtransport-http3-
draft02` — the Chrome/draft02 dialect. That is neither the current
profile (WT_ENABLED, `webtransport-h3`) nor the D13/14 compat profile
(WT_MAX_SESSIONS 0x14e9cd29, `webtransport`). Interoperating with imquic
would require a SEPARATE third typed profile (D07/Chrome); it is
proposed for a future slice and the compat profile is deliberately NOT
widened to accept D07/Chrome signals.

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
  documented parity exception (the MsQuic backend, whose receive window is
  a hard bound, does throttle the peer); no private API is used to close it.
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
