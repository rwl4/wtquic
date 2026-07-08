# Compatibility note

For consumers pinning wtquic as a dependency (e.g. libmoq's setup
script). The durable revision is the annotated tag below — pin the tag
or its exact commit SHA; both stay fetchable regardless of later
history rewrites on `main`.

**Dependency point: `v0.1.0-preview.1`.**

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

REMAINING LIMITATION: a wtquic *client* talking to a THIRD-PARTY H3
server that bootstraps eagerly (sends its control stream at
handshake-complete, as most do) can still lose that stream to the OS
race. wtquic cannot fix the peer; expect rare establishment wedges on
such servers until Apple fixes the drop, and bound establishment with
the owning layer's connect deadline.

## Trust failure classification (`NW_TRUST`)

Server certificate/trust rejection on the secure path fails fast and
seals a first-causal transport-error record with
`native_domain == WTQ_ERRDOM_NW_TRUST` (a dedicated domain: classify
trust failure by PROVENANCE — this evaluator rejected the chain — not
by an OSStatus allowlist; `native_code` carries the OSStatus, e.g.
errSecNotTrusted). `insecure_skip_verify` remains a test-only bypass.
Pre-ready failures with no local observation (dead port, DNS) remain
invisible on this SDK; the owning layer's connect timeout governs.
