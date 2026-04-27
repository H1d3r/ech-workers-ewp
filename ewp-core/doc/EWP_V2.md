# EWP v2 — Protocol Specification

> Status: **normative**, this document is the single source of truth.
> Implementations that disagree with this document are wrong.
>
> This protocol intentionally has **no version negotiation, no downgrade,
> no compatibility with v1**. A v1 peer attempting to speak to a v2 peer
> MUST be rejected immediately.

---

## 0. Design constraints

1. **Confidentiality and integrity of every byte after the handshake**, not
   just the handshake itself.
2. **Forward secrecy** for every session, via ephemeral X25519.
3. **Post-quantum hybrid** key exchange via ML-KEM-768, in addition to
   classical X25519. The session key derives from BOTH shared secrets;
   compromise of either one alone leaks nothing.
4. **No plaintext fallback path exists in code.** There is no
   "direct copy / vision / skip-aead" branch. Anyone proposing one is wrong.
5. **One frame format covers everything**: TCP data, UDP data, control,
   padding. There is no second framing layer.
6. **The transport layer (WS/gRPC/H3/xhttp) MUST NOT understand the
   protocol bytes.** Transports only carry message-bounded opaque blobs.

---

## 1. Cryptographic primitives (fixed, no negotiation)

| Purpose                | Algorithm                       |
|------------------------|---------------------------------|
| AEAD                   | ChaCha20-Poly1305 (RFC 8439)    |
| Classical KEM          | X25519 (RFC 7748)               |
| PQ KEM                 | ML-KEM-768 (FIPS 203)           |
| KDF                    | HKDF-SHA-256 (RFC 5869)         |
| Outer integrity (handshake only) | HMAC-SHA-256, truncated to 16 bytes |

The choice of ChaCha20-Poly1305 over AES-GCM is deliberate: every modern
mobile and server CPU runs ChaCha20 in software at >1 GiB/s without any
hardware acceleration. Ubiquitous performance, no need for special CPU
features, and no timing-side-channel concerns from non-AES-NI fallback paths.

X25519 + ML-KEM-768 hybrid handshake costs roughly 60–700 µs per session
on the slowest currently-shipping ARM cores; this is two orders of
magnitude smaller than typical TLS 1.3 setup latency, so the hybrid PQ
overhead is irrelevant to user perception.

---

## 2. Wire format — handshake

EWP v2 sits **inside** an outer TLS 1.3 (with ECH) tunnel. The handshake
described below is the **inner** handshake, exchanged as the first
message-bounded payload after the outer transport (WS/gRPC/H3/xhttp)
delivers its first message.

### 2.1 ClientHello

```
+----------------+--------+-------------------------------------------------+
| Field          | Size   | Notes                                           |
+----------------+--------+-------------------------------------------------+
| Magic          | 4      | ASCII "EWP2" (0x45 0x57 0x50 0x32). A v1 peer   |
|                |        | will fail to parse this; v2 servers MUST drop   |
|                |        | the connection on mismatch with no response.    |
| Nonce          | 12     | crypto/rand, used as ChaCha20-Poly1305 nonce    |
|                |        | for the encrypted plaintext below AND as part   |
|                |        | of the HKDF salt.                               |
| ClassicalPub   | 32     | Client's ephemeral X25519 public key.           |
| PQPub          | 1184   | Client's ephemeral ML-KEM-768 encapsulation key.|
| CTLen          | 2      | Length (big-endian) of the encrypted plaintext  |
|                |        | that follows, including the 16-byte Poly1305    |
|                |        | tag. Maximum 4096.                              |
| Ciphertext     | CTLen  | ChaCha20-Poly1305 of Plaintext below;           |
|                |        | key   = HKDF(UUID || Magic || Nonce || ...);    |
|                |        | nonce = first 12 bytes = the Nonce field;       |
|                |        | aad   = all preceding fields verbatim.          |
| OuterMAC       | 16     | HMAC-SHA-256(SHA-256(UUID), all preceding       |
|                |        | bytes including Ciphertext) truncated to 16.    |
|                |        | Allows the server to reject unknown UUIDs       |
|                |        | before doing X25519/ML-KEM math.                |
+----------------+--------+-------------------------------------------------+

Plaintext layout (encrypted under PSK derived from UUID):

+----------------+--------+-------------------------------------------------+
| Field          | Size   | Notes                                           |
+----------------+--------+-------------------------------------------------+
| Timestamp      | 4      | Unix seconds (big-endian). Server rejects if    |
|                |        | abs(now - ts) > 120.                            |
| UUID           | 16     | Repeated inside the encrypted payload to bind   |
|                |        | it to the AEAD authenticator.                   |
| Command        | 1      | 0x01 = TCP, 0x02 = UDP. No other values.        |
| Address        | n      | See §4 for encoding.                            |
| PadLen         | 2      | Big-endian; random padding length [64, 1024].   |
| Pad            | PadLen | crypto/rand.                                    |
+----------------+--------+-------------------------------------------------+
```

### 2.2 ServerHello

```
+----------------+--------+-------------------------------------------------+
| Field          | Size   | Notes                                           |
+----------------+--------+-------------------------------------------------+
| Magic          | 4      | "EWP2".                                         |
| NonceEcho      | 12     | Verbatim copy of ClientHello.Nonce.             |
| ClassicalPub   | 32     | Server's ephemeral X25519 public key.           |
| PQCipher       | 1088   | ML-KEM-768 ciphertext, encapsulated against     |
|                |        | client's PQPub.                                 |
| ServerTime     | 4      | Server's Unix seconds (informational).          |
| Status         | 1      | 0x00 = OK, anything else = abort.               |
| OuterMAC       | 16     | HMAC-SHA-256(SHA-256(UUID), all preceding) [:16]|
+----------------+--------+-------------------------------------------------+
```

There is **no** "fake response" path. A server that cannot satisfy the
request closes the underlying transport without writing a ServerHello.
The outer TLS layer already provides the only honest signal a probe
will get.

### 2.3 Key derivation (post-handshake)

```
shared_classic = X25519(client_eph_priv, server_classical_pub)
shared_pq      = ML-KEM-768.Decaps(client_pq_priv, PQCipher)
ikm            = shared_classic || shared_pq
salt           = "EWPv2-salt" || ClientHello.Nonce || ServerHello.NonceEcho
K_master       = HKDF-Extract(salt, ikm)

K_c2s          = HKDF-Expand(K_master, "EWPv2 c2s key",   32)
K_s2c          = HKDF-Expand(K_master, "EWPv2 s2c key",   32)
NP_c2s         = HKDF-Expand(K_master, "EWPv2 c2s nonce",  4)
NP_s2c         = HKDF-Expand(K_master, "EWPv2 s2c nonce",  4)
```

Both sides discard the ephemeral private keys and the PSK-derived
handshake AEAD key as soon as derivation completes.

---

## 3. Wire format — data frames

After the handshake, every byte exchanged in either direction is a
sequence of frames in this exact format:

```
+----------------+--------+-------------------------------------------------+
| Field          | Size   | Notes                                           |
+----------------+--------+-------------------------------------------------+
| FrameLen       | 4      | Big-endian length of the rest of the frame      |
|                |        | (everything after this field, INCLUDING Pad).   |
|                |        | Hard cap 65 536 bytes.                          |
| Counter        | 8      | Big-endian, monotonically increasing per        |
|                |        | direction, starts at 0.                         |
| FrameType      | 1      | See §3.2.                                       |
| MetaLen        | 2      | Big-endian length of Meta, in [0, 1024].        |
| PadLen         | 2      | Big-endian, in [0, 4096]. Random length.        |
| Cipher         | M      | ChaCha20-Poly1305(Meta || Payload),             |
|                |        | M = MetaLen + len(Payload) + 16.                |
|                |        | key   = K_dir;                                  |
|                |        | nonce = NP_dir (4 bytes) || Counter (8 bytes);  |
|                |        | aad   = FrameLen || Counter || FrameType        |
|                |        |       || MetaLen || PadLen.                      |
| Pad            | PadLen | crypto/rand. Not authenticated for content      |
|                |        | (PadLen IS authenticated through AAD).          |
|                |        | Receivers read it to keep the byte stream       |
|                |        | synchronized and then discard it.               |
+----------------+--------+-------------------------------------------------+
```

`Pad` content is intentionally outside the AEAD body: this gives
DPI/middleware no oracle for tampering detection while keeping the auth
tag covering exactly what the application cares about. `PadLen` itself
IS in AAD, so an attacker cannot silently truncate or extend the pad
region without invalidating the next frame's framing.

### 3.1 Counter discipline

* Sender increments its `Counter` by exactly 1 per frame written.
* Receiver MUST reject any frame whose `Counter` is not exactly
  `expected_counter`, with no reordering tolerance: the underlying
  transport is reliable and ordered. On mismatch, the receiver MUST
  close the SecureStream, free both AEAD instances, and return an error
  to the application.
* When `Counter` reaches `2^63`, the SecureStream MUST initiate rekey
  (see §3.3) before sending the next frame. (This is a future-proofing
  trigger; in practice rekey fires far earlier on byte volume.)

### 3.2 FrameType registry

```
0x01  TCP_DATA       Meta empty;       Payload = TCP bytes
0x02  UDP_DATA       Meta = UDPMeta;   Payload = UDP datagram
0x03  UDP_NEW        Meta = UDPMeta;   Payload = optional initial datagram
0x04  UDP_END        Meta = GlobalID;  Payload empty
0x05  UDP_PROBE_REQ  Meta = GlobalID;  Payload empty
0x06  UDP_PROBE_RESP Meta = ProbeMeta; Payload empty
0x10  PING           Meta empty;       Payload = opaque ping cookie
0x11  PONG           Meta empty;       Payload = echo of PING cookie
0x12  REKEY_REQ      Meta empty;       Payload = X25519Pub(32) || MLKEMPub(1184)
0x13  REKEY_RESP     Meta empty;       Payload = X25519Pub(32) || MLKEMCipher(1088)
0x20  PADDING_ONLY   Meta empty;       Payload = ignored (cover traffic)
```

All other values MUST cause the receiver to close the SecureStream.

#### Meta encodings

```
GlobalID  := 8 bytes, generated by the client side via crypto/rand on
             UDP_NEW, never derived from any address. Identifies one UDP
             sub-session within a SecureStream.

UDPMeta   := GlobalID(8) || Address (see §4)

ProbeMeta := GlobalID(8) || Address (server-observed external mapping
             for that sub-session, in the same Address encoding).
```

### 3.3 Rekey

Either side MAY send `REKEY_REQ` at any time after the initial
handshake. Triggers (whichever fires first):

* `bytes_since_last_rekey >= 8 GiB` in either direction
* `seconds_since_last_rekey >= 3600`
* Application-level explicit request (e.g. about to expose long-lived
  session through a flagged transport).

Procedure:

1. Initiator generates fresh ephemeral X25519 + ML-KEM-768 keys, sends
   `REKEY_REQ`, **continues sending data under the OLD keys** until the
   `REKEY_RESP` arrives.
2. Responder generates fresh X25519 keys, runs ML-KEM-768.Encaps against
   the initiator's MLKEMPub, sends `REKEY_RESP`. From the moment it
   sends `REKEY_RESP`, the responder writes new frames under the
   **new** key (counters reset to 0 for the responder->initiator
   direction).
3. Upon receiving `REKEY_RESP`, the initiator switches its
   initiator->responder direction to the new key (counter resets to 0
   for that direction).

The two directions thus rekey independently and asynchronously. Old
keys are discarded as soon as the local direction has switched. Receivers
MUST keep at most TWO key generations live (current and previous) per
direction, to absorb in-flight frames sent before the peer's switch.

---

## 4. Address encoding

```
AddrType  | Layout
----------+-----------------------------------------------------------------
0x01      | type(1) || ipv4(4) || port(2)
0x02      | type(1) || ipv6(16) || port(2)
0x03      | type(1) || domainLen(1) || domain(n) || port(2)
```

Domains MUST be valid LDH (RFC 1123) labels and MUST NOT exceed 253
bytes total. The address encoding is identical wherever an address
appears (handshake plaintext, UDPMeta, ProbeMeta).

---

## 5. UDP semantics

A SecureStream multiplexes any number of UDP sub-sessions, each
identified by a `GlobalID`.

### 5.1 Client side

* The client TUN handler maintains **one SecureStream per real client
  source address** (`netip.AddrPort`). Multiple destinations are NOT
  separate tunnels.
* For each (client-src, destination) pair seen on TUN, the client picks
  a fresh `GlobalID` (crypto/rand) and emits `UDP_NEW`, with subsequent
  datagrams as `UDP_DATA`.
* On receipt of any inbound `UDP_DATA`, the client looks at the
  `Address` in `UDPMeta` (the **real remote** as observed by the
  server's `ListenUDP`), and writes the payload back into the gVisor
  TUN with that real-remote as the response source. The client MUST
  maintain a per-(src, real-remote) write endpoint cache so that
  responses from a previously-unseen real-remote (e.g. STUN reflection)
  are delivered with the correct source address.

### 5.2 Server side

* On `UDP_NEW` the server creates a fresh non-connected
  `net.ListenUDP(":0")` socket bound to that `GlobalID`. The
  destination Address from UDPMeta is recorded as the sub-session's
  default target.
* On `UDP_DATA` the server uses the per-frame Address (if present) as
  the **single-frame** target; it MUST NOT update the sub-session's
  default target. (This preserves multi-target client semantics, e.g.
  STUN consistency probes.)
* The server's per-sub-session receive goroutine reads from
  `ListenUDP`. Each received datagram becomes a `UDP_DATA` frame with
  `UDPMeta.Address = the real remote 5-tuple observed by ReadFromUDP`.
* On idle timeout OR socket error, the server MUST emit `UDP_END` to
  the client before closing the sub-session. Silent close is
  prohibited.

### 5.3 NAT consistency probe

Either side MAY emit `UDP_PROBE_REQ` for any active GlobalID. The
counterpart MUST respond with `UDP_PROBE_RESP` containing
`UDPMeta.Address` set to whatever it observes the **other side's
external mapping** to be:

* Server responding to client probe: `Address = ListenUDP socket's
  externally-visible mapping`. Server MAY use a built-in STUN bootstrap
  (run once at server startup, cached) to learn its own public IP.
* Client responding to server probe: `Address = TUN-side observed
  source` of the corresponding flow.

A client running a NAT classification routine emits `UDP_PROBE_REQ`
across multiple sub-sessions targeting different STUN servers; the
collected `UDP_PROBE_RESP` data identifies the NAT type unambiguously.

---

## 6. Outer transport contract

The TunnelConn interface in `transport/transport.go` is reduced to:

```go
type TunnelConn interface {
    SendMessage(b []byte) error      // one whole message, atomic
    ReadMessage() ([]byte, error)    // one whole message, atomic
    Close() error
}
```

A "message" is whatever the underlying transport delivers as a single
unit:

* WebSocket: one binary frame.
* gRPC: one `SocketData` proto.
* H3 / gRPC-Web: one length-prefixed frame.
* xhttp `stream-one`: one length-prefixed body chunk.

Transports MUST NOT understand or modify the bytes inside a message.
Transports MUST NOT split a message across multiple `ReadMessage`
returns. Transports MUST NOT coalesce multiple messages into one
`ReadMessage` return.

The first message of every connection is the EWP v2 ClientHello; the
second is the ServerHello; everything after is data frames.

---

## 7. Threat model and explicit non-goals

### Defended against

* Eavesdropping on the wire by anyone who does not hold both ephemeral
  private keys (X25519 and ML-KEM).
* Active MITM of EWP v2 frames after handshake (AEAD + counter).
* Replay of past sessions (handshake nonce + counter discipline).
* Statistical traffic analysis based on payload length (per-frame
  random padding outside the AEAD).
* "Store now, decrypt later" with future quantum hardware (PQ KEM).
* Compromise of the long-lived UUID **leaks past sessions only if the
  attacker also recorded the corresponding session's traffic AND
  breaks both X25519 and ML-KEM-768**. Forward secrecy follows from
  ephemeral key destruction.

### Explicitly NOT defended

* Compromise of the underlying TLS/ECH layer's identity (the server
  certificate). EWP v2 does not authenticate the server independently
  of TLS.
* Traffic-volume side channels that are not specific to length-per-frame
  (e.g. inter-arrival timing, total bytes per direction).
* Fingerprinting of the v2 ClientHello length distribution itself by a
  network observer who can also see the outer TLS handshake length.
  Mitigation is outside the scope of EWP v2; users who need
  domain-fronting-style cover should configure the outer TLS layer
  accordingly.

### Explicitly forbidden

* "Direct copy" / "Vision" / any branch that bypasses AEAD. Such a
  branch MUST NOT be added; reviewers MUST reject any such PR.
* Negotiated cipher suites or KEM choices. The algorithms in §1 are
  fixed for the lifetime of v2.
* Compatibility with v1 peers. Mixed v1/v2 deployments are not
  supported.

---

## 8. Test obligations

Any implementation of this spec MUST pass:

1. **TestNoPlaintextOnWire** — record the byte stream of a real
   transport, decrypt the handshake, then assert that no Cipher region
   contains the strings `"GET "`, `"HTTP/"`, or the TLS ClientHello
   magic (`0x16 0x03 0x01`–`0x16 0x03 0x04`).
2. **TestSTUNConsistency** — open one SecureStream from a fixed client
   src, emit four UDP_NEW + UDP_DATA pairs targeting four distinct
   STUN servers, and assert that all four responses arrive with
   `UDPMeta.Address` matching their respective STUN server's public
   address.
3. **TestReplayDropped** — feed a captured ciphertext frame back into
   the receiver's input twice; the second feed MUST cause the
   SecureStream to close.
4. **TestRekeyEnforced** — force a rekey by writing > 8 GiB of frames;
   inspect the on-wire counters and assert that they reset to 0 on
   each direction's switch boundary.
5. **TestHandshakeMagicMismatchKills** — inject a single byte
   alteration into the ClientHello Magic; the server MUST close
   without writing a ServerHello.
