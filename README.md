# wtquic

A purpose-built **WebTransport over HTTP/3** library in C, designed for
performance. wtquic implements the minimal HTTP/3 subset that
WebTransport requires (extended CONNECT, static-only QPACK, SETTINGS,<!-- api-boundary-exempt: deliberate scope description -->
capsules, stream/datagram association) — not a general HTTP/3 stack — and
gets out of the way of your data.

- **Design**: a sans-I/O, callback-driven protocol engine over a small
  backend driver interface. After a stream is associated with a session,
  payload bytes flow directly between your application and the transport —
  zero copies, zero queues, zero steady-state allocations inside wtquic.
- **Spec**: draft-ietf-webtrans-http3-16 for the current profile —
  native-H3 WebTransport with `:protocol = webtransport-h3` (bare
  `webtransport` is capsule-based WebTransport); an explicit opt-in
  drafts-13/14 compatibility profile is available (see below). Legacy
  SETTINGS codepoints are still accepted on receive.
- **Backends**: [MsQuic](https://github.com/microsoft/msquic) (primary;
  client + server) and **Apple Network.framework** (client-only, no
  external dependency; macOS 13 / iOS 16 or later).
- **License**: MIT.

## Status: public preview

This is a **preview, not a stable release**. The API is not frozen —
struct layouts are versioned (`struct_size` prefixes) and additions are
append-only, but names and semantics may still change before 0.1 is
tagged. The MsQuic backend is the primary working backend and carries
the full test surface (unit, deterministic simulation with seeded
faults, fuzzing, allocation-failure sweeps, real-loopback tests). The
Network.framework client backend carries its own lifecycle, loopback
(against a real MsQuic server), send-matrix, and sanitizer suites.

## WebTransport profiles

wtquic speaks three WebTransport-over-HTTP/3 wire profiles. A **client**
requests one per connection (`wtq_connect_config_t.webtransport_profile`).
A **server** configures a capability SET per listener
(`wtq_msquic_listener_cfg_t.webtransport_profiles`), advertises the union
of it, and then selects ONE profile per connection from the peer's
settings:

| | `H3_CURRENT` (default) | `H3_DRAFT_13_14_COMPAT` |
|---|---|---|
| extended CONNECT `:protocol` | `webtransport-h3` | `webtransport` |
| WebTransport setting emitted | WT_ENABLED (0x2c7cf000) = 1 | WT_MAX_SESSIONS (0x14e9cd29) = 1 |
| WT flow-control settings | none | none (flow control disabled) |
| peer setting accepted as WT | WT_ENABLED = 1 | WT_MAX_SESSIONS > 0 |
| interop | wtquic draft-16 self-loopback | proxygen/moxygen, picoquic h3zero (moqx, pico_wt) |

Selection happens once, from the peer's settings, by explicit
newest-first precedence, and before the extended CONNECT is processed.
The `:protocol` token then **validates** that selection rather than
choosing it — several draft generations share the bare `webtransport`
token, so a token cannot identify one on its own. A token that does not
match the selected profile gets a generic 400 and the connection stays
usable; peers sharing no profile simply never establish, with **no
fallback and no retry**.

```c
/* one listener serving both generations */
lcfg.webtransport_profiles = WTQ_WEBTRANSPORT_PROFILES_ALL;

/* what THIS session actually selected (valid from on_established on) */
wtq_webtransport_profile_t prof;
if (wtq_session_webtransport_profile(session, &prof) == WTQ_OK)
    use(prof);
```

A listener that leaves the set zero keeps the older singular
`webtransport_profile` behavior exactly, so existing callers are
unaffected.

**`H3_CURRENT` and `H3_DRAFT_13_14_COMPAT` do not provide stock-browser
compatibility.** A third profile, `H3_DRAFT_02_RFC9297_COMPAT`, does:
draft-02 WebTransport signaling and the 8-bit outbound stream-error contract
carried over **RFC 9297** datagrams. It is **not** byte-faithful draft-02/-05:
the legacy datagram codepoint `0xffd277` is neither emitted nor accepted, no
datagram context/registration is implemented, and D07 `0xc671706a` is not
supported. Evidence status: **proven against exact Google Chrome
152.0.7977.66**; Firefox 155 is source-coherent but has **no exact-binary live
row yet**; **no Safari claim**. Profile selection is from peer SETTINGS only,
with an explicit Origin requirement and **no heuristic fallback**.
Published evidence points at stable Chrome and Firefox emitting the older
draft-02 `ENABLE_WEBTRANSPORT` (0x2b603742) — a different generation from
the drafts-7–12 codepoint (0xc671706a). wtquic emits **`0x2b603742`** for
`H3_DRAFT_02_RFC9297_COMPAT` and **never** emits `0xc671706a`. No
Safari support is claimed without capture evidence. See COMPATIBILITY.md.

No live third-party draft-16 relay (a peer signalling WT_ENABLED with
`:protocol = webtransport-h3`) is available here, so the current profile
is exercised by wtquic self-loopback.

On imquic, note that what a peer ACCEPTS and what it EMITS are separate
observations. HEAD 99fa77d **emits** `:protocol = webtransport` with
`ENABLE_WEBTRANSPORT` (0x2b603742) — the draft-02 generation — alongside
`WEBTRANSPORT_MAX_SESSIONS` (0xc671706a), which is the distinct
drafts-7–12 generation. Those are two different generations and are not
one "Chrome" dialect. wtquic emits `0x2b603742` only, never `0xc671706a`, and implements no
profile that selects on them. Interoperating would need a separately
typed, separately evidenced profile, which is not added here.

All three profiles share everything below the H3 SETTINGS/CONNECT layer —
stream preambles, quarter-stream-ID datagrams, application <!-- api-boundary-exempt: deliberate profile-scope description -->
error-code mapping, RESET_STREAM_AT requirements, and CLOSE / DRAIN /
teardown are identical. The compatibility profile is safe only because it
is EXPLICIT: the bare `webtransport` token also names capsule-based
WebTransport in the current architecture, so it is used only when paired
with the historical drafts-13/14 H3 SETTINGS dialect.
`H3_DRAFT_13_14_COMPAT` never advertises the current settings and never
emits the drafts-7–12 codepoint (0xc671706a). A server's selection is
per connection and is driven by the peer's settings intersected with the
listener's configured set — never by a heuristic, a per-request fallback,
or the CONNECT token alone.

## Compliance note (reliable reset)

draft-ietf-webtrans-http3-16 requires the RESET_STREAM_AT QUIC extension
(draft-ietf-quic-reliable-stream-reset) when resetting WebTransport data
streams. MsQuic currently implements an older, wire-incompatible iteration
of that extension behind a preview build flag. Consequently:

> **Both backends are draft-16 WebTransport-compatible in *lenient
> mode*: strict RESET_STREAM_AT conformance is capability-gated and is
> skipped unless negotiated.** A stream reset before its
> session-association header was sent never joins the session.
> Network.framework exposes no reset-at control at all. Full strict
> conformance is only claimable on a backend whose QUIC stack
> implements the current RESET_STREAM_AT draft; none of the current
> ones does.

## Dependencies

- CMake ≥ 3.24 and a C11 compiler (public headers are also
  C++-includable).
- **MsQuic ≥ 2.5.9**, for the real backend. Discovery, in order:
  - an installed `msquic` CMake package on the prefix path (on macOS,
    Homebrew's `libmsquic` provides one),
  - the `WTQ_MSQUIC_ROOT` cache variable pointing at an MsQuic
    build/install (default fallback: a sibling `../msquic` checkout),
  - `msquic_DIR` pointing directly at the package's CMake directory.

Without a current MsQuic present, the core library, protocol code,
simulator, and their tests still build and pass
(`WTQ_BUILD_MSQUIC=AUTO` skips the backend). Make a missing or too-old
MsQuic a configure error instead with:

```sh
cmake -S . -B build/default -DWTQ_REQUIRE_MSQUIC=ON
```

The **Network.framework backend** has no external dependency (Apple SDK
only) and is opt-in:

```sh
cmake -S . -B build/default -DWTQ_BUILD_NETWORK=ON
```

## Building and testing

```sh
cmake --preset default            # RelWithDebInfo + tests
cmake --build build/default -j
ctest --test-dir build/default --output-on-failure
```

Other presets: `asan` (ASan + UBSan), `shared` (shared library +
exported-symbol policy checks), `fuzz` (libFuzzer targets; needs a
clang with the fuzzer runtime).

The real-transport loopback suite runs under ctest with generated
self-signed certificates, or directly:

```sh
scripts/gen_test_certs.sh build/default/tests/certs
./build/default/tests/loopback_msquic build/default/tests/certs
```

## Installing and consuming

```sh
cmake --install build/default --prefix <prefix>
```

CMake package (the fully supported path):

```cmake
find_package(wtquic CONFIG REQUIRED COMPONENTS msquic)  # and/or network
target_link_libraries(app PRIVATE wtq::msquic)   # or wtq::network,
                                                 # or wtq::wtquic (core only)
```

`pkg-config` files (`wtquic.pc`, `wtquic-msquic.pc`,
`wtquic-network.pc`) are installed and relocatable (prefix-relative);
`wtquic-msquic.pc` expresses the MsQuic dependency only as a private
link hint, while `wtquic-network.pc` carries the Apple framework link
flags. CMake consumption is the first-class path.

## Usage sketch

Everything is callback-driven; there is no poll loop to run. Callbacks
fire on the transport's worker for that connection (serialized per
connection, never concurrently for one session).

```c
#include <wtquic/wtquic.h>
#include <wtquic/wtquic_msquic.h>

/* events: on_established / on_stream_opened / on_stream_data /
 * on_send_complete / on_closed ... (NULL members are skipped) */
static wtq_session_events_t EV; /* wtq_session_events_init(&EV) + fill */

wtq_msquic_env_cfg_t ecfg = WTQ_MSQUIC_ENV_CFG_INIT;
wtq_msquic_env_t *env = NULL;
wtq_msquic_env_open(&ecfg, &env);

/* server */
wtq_serve_config_t path = WTQ_SERVE_CONFIG_INIT;
path.path = "/echo";
wtq_msquic_listener_cfg_t lcfg = WTQ_MSQUIC_LISTENER_CFG_INIT;
lcfg.port = 4433;
lcfg.cert_file = "cert.pem";
lcfg.key_file = "key.pem";
lcfg.paths = &path;
lcfg.path_count = 1;
lcfg.events = &EV;
wtq_msquic_listener_t *listener = NULL;
wtq_msquic_listener_start(env, &lcfg, &listener);

/* client */
wtq_connect_config_t cc;
wtq_connect_config_init(&cc);
cc.authority = "example.org";
cc.path = "/echo";
wtq_msquic_client_cfg_t ccfg = WTQ_MSQUIC_CLIENT_CFG_INIT;
ccfg.server_name = "example.org";
ccfg.port = 4433;
ccfg.connect = &cc;
ccfg.events = &EV;
wtq_session_t *session = NULL;
wtq_msquic_client_connect(env, &ccfg, &session);

/* inside callbacks: wtq_session_open_uni/bidi, wtq_stream_send
 * (data borrowed until on_send_complete), wtq_session_send_datagram,
 * wtq_session_close ... */

/* teardown: close sessions, stop the listener, then env_close —
 * which BLOCKS until every connection has fully torn down */
wtq_msquic_listener_stop(listener);
wtq_msquic_env_close(env);
```

The **Network.framework client** (`<wtquic/wtquic_network.h>`) speaks
the same session/stream API but adds a managed connection lifecycle:
the backend owns one serial dispatch queue per connection (the
*serialization domain*), and — unlike MsQuic — the domain can be
entered from any thread:

```c
wtq_nw_conn_cfg_t ncfg = WTQ_NW_CONN_CFG_INIT;
ncfg.server_name = "example.org";
ncfg.port = 4433;
ncfg.connect = &cc;
ncfg.events = &EV;
ncfg.on_stopped = done_cb;      /* the FINAL app-visible block */
wtq_nw_conn_t *conn = NULL;
wtq_nw_conn_create(&ncfg, &conn);

wtq_nw_conn_post(conn, fn, ctx); /* run fn(ctx) on the domain:
                                    accepted-runs-once, in order */

/* or the preallocated doorbell (cfg.on_doorbell): a NON-ALLOCATING,
   infallible, coalescing wake from any thread — post() allocates a
   node per submission and can report NOMEM; a ring cannot */
wtq_nw_conn_doorbell_ring(conn);

/* the same doorbell on a delay, from a timer preallocated at connection
   construction (no per-arm object, no callback closure, no configured/
   backend allocator call, no timer thread): one delayed slot, a new arm
   replaces it, cancel_after clears it. delay is host uptime; returns
   CLOSED after stop_begin. Legal only on a valid retained handle. */
wtq_nw_conn_doorbell_ring_after(conn, 5000 /* us */);
wtq_nw_conn_doorbell_cancel_after(conn);

/* teardown: nonblocking begin from anywhere (callbacks included),
   then either join off-domain or resume from on_stopped */
wtq_nw_conn_stop_begin(conn);
wtq_nw_conn_join(conn);
wtq_nw_conn_release(conn);
```

Ownership and threading contracts are documented in detail on each
declaration in `include/wtquic/`.

## Known limitations (preview)

- **Strict RESET_STREAM_AT conformance is deferred** (see the compliance
  note above); resets degrade to plain RESET_STREAM on MsQuic.
- **Callback confinement**: callback dispatch and every session/stream
  operation — refcounts and queries included — share one serialization
  domain; nothing is internally locked. Calls from inside the session's
  callbacks are always legal; whether (and how) the domain can be
  entered from outside a callback is backend-defined. On MsQuic an
  unguarded session has no out-of-callback entry: operate only from
  that session's callbacks, except that a retained session may be
  inspected and released from any thread once `wtq_msquic_env_close`
  has returned. A session created with a `wtq_guard_t` widens this —
  the backend brackets that session's callbacks with the guard, so the
  caller may run its operations from any thread while holding the
  guard. Blocking teardown (`env_close`, `listener_stop`) must not be
  called from a callback, nor while holding the guard. On
  Network.framework, `wtq_nw_conn_post` is the
  out-of-callback entry, and teardown is split (`stop_begin` anywhere,
  `join` off-domain only).
- **Network.framework is client-only** (no listener). Certificate/trust
  rejection fails fast — an explicit verifier seals a first-causal
  error record in the dedicated `NW_TRUST` domain (classify trust
  failure by provenance, not by OSStatus allowlist). Pre-ready failures
  with no local observation (dead port, DNS) remain invisible on that
  SDK — no state transition carries them, so the owning layer's connect
  timeout governs. Errors NW does deliver are mapped into the
  transport-error record.
- **No held-buffer receive API yet**: received data is borrowed for the
  duration of the callback; copy what must outlive it. Receive
  pause/resume exists (`wtq_stream_pause_receive` /
  `wtq_stream_resume_receive`) and **arrests application delivery**: pause
  stops arming *future* receives, but because Network.framework's receive
  is a pull, one `nw_connection_receive` is always outstanding, so the
  completion queued behind a pause can still fire. That one completion is
  held backend-local — its transport buffer is RETAINED (zero-copy, never
  copied) and, for a pure FIN, remembered — and is never delivered to the
  application while paused; resume replays it exactly once, in order (FIN
  included), then arms the next receive. **Transport-level peer
  backpressure is NOT guaranteed on this backend**: the public
  initial-window setters are values Network.framework auto-tunes upward,
  and it buffers/ACKs past them, so a paused peer is bounded only by the
  framework's internal receive buffering, not by the advertised window (a
  documented parity exception — see `COMPATIBILITY.md`). This is not a
  hidden footnote: the guarantee is typed.
  `wtq_stream_receive_pause_mode()` reports
  `WTQ_RECEIVE_PAUSE_DELIVERY_ONLY` for the Network backend and
  `WTQ_RECEIVE_PAUSE_FLOW_CONTROLLED` for the MsQuic backend (its logical
  pause arrests even an already-queued RECEIVE synchronously and extends no
  receive credit while paused, so the peer is eventually blocked by QUIC
  flow control). A memory-sensitive caller branches on the mode (accept
  delivery isolation, or refuse/close) rather than assuming a bound that
  the Network backend does not provide.
- The bundled `examples/` are stubs pending the convenience-layer
  ergonomics pass.

## CI

GitHub Actions runs the core-only build/test matrix (macOS + Ubuntu,
Debug/Release, gcc + clang) and the shared-library symbol-policy lane —
both without MsQuic. The backend-driven suites (MsQuic loopback,
conformance, and backend units; the Network.framework lifecycle and
loopback lanes), the fuzzers, and the allocation-failure sweeps run in
local development; hosted backend lanes are a follow-up.

## Author

Raymond Lucke
