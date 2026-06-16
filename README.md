# Steganography in TCP Packets

A proof-of-concept for bidirectional covert communication embedded in TCP packet headers, built entirely in user space. Data hides in the least significant bits of the TCP Timestamp Option (TSval field), encrypted with a XOR cipher, over ordinary HTTP traffic.

Three nodes: **Alice** (sender/C2 target), **Bob** (server/C2 operator), and a **Warden** (intermediate router that monitors and optionally impairs the connection). Both Alice and Bob run as user-space proxies that intercept TCP flows via iptables NFQUEUE, modify packets in flight, and pass them on.

## How it works

**Session initiation** uses the TCP Initial Sequence Number as a covert knock. The high 16 bits are random, the low 16 hold a truncated HMAC-SHA256 tag computed over the random bits and the current 15-second time window. Bob checks incoming SYNs for a valid tag, if one matches, both sides derive a shared session key via HKDF over their respective ISNs.

Replacing the ISN desynchronizes the kernel TCP stack from wire sequence numbers, so both sides apply a constant translation offset to all subsequent sequence and acknowledgment numbers.

**Payload encoding** embeds N bits (1–8, configurable) into the LSBs of each packet's TSval. Each packet gets a unique keystream derived from its sequence/acknowledgment pair and the session key.

Frames start with an 11-bit Barker code, followed by a 16-bit length prefix and the payload. An optional jitter buffer reorders out-of-order packets before decoding to eliminate bit errors from network reordering.

## Running it

Requires Docker and Docker Compose.

```bash
docker-compose up
```

Builds and starts all three containers. Alice initiates an HTTP request to Bob through the Warden and the covert channel opens. Bob sends `src/secret/bobs_secret.txt` to Alice. Alice executes any commands it receives and sends back the output.

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `JITTER_ENABLED` | `1` | Enable the jitter buffer on Alice |
| `EXECUTE_COMMANDS` | `1` | Alice executes received data as shell commands |
| `REORDER_PCT` | `25` | Packet reorder percentage applied by the Warden |

Example with impairments and command execution off:

```bash
JITTER_ENABLED=0 EXECUTE_COMMANDS=0 REORDER_PCT=0 docker-compose up
```

For standalone Alice or Bob, see `vps_stuff/`.

## Experiments branch

The `experiments` branch covers the detectability analysis. It adds a `--mitigated` flag (also `MITIGATED` in Docker Compose) that enables clock-tick gating: the proxy injects bits only when the kernel TCP clock has actually ticked since the last packet. The TSval increment distribution ends up much closer to unmodified traffic.

Three variants:

- **V1** — original implementation, 2 bpp, inter-packet delays enabled
- **V2** — inject-on-kernel-tick, 2 bpp, delays disabled
- **V3** — inject-on-kernel-tick, 1 bpp, delays disabled (the hardened variant)

Captures came from 50 MB HTTP transfers between two VPS instances (Bob on US West Coast, Alice in Finland): ten runs per variant, plus a baseline of unmodified traffic. Raw pcaps are in `experiments/captures/`, organized by variant.

Detection used three unsupervised classifiers: Isolation Forest, One-Class SVM, and a Gaussian Mixture Model. They are trained on baseline traffic. V1 is reliably caught by OCSVM (AUC 0.993). V2 drops that to near-random (AUC 0.479). V3 falls below the 5% false-positive threshold on all three.

Analysis scripts in `experiments/scripts/`:

- `features.py` — extracts TSval difference statistics from pcaps
- `overhead_analysis.py` — measures transfer time decomposed by source of overhead
- `plot_jitter_results.py` — bit error rate across reorder rates, with and without the jitter buffer
- `unsupervised_detection.py` — runs the full detection pipeline, writes results to `experiments/outputs/`

Check out the `experiments` branch to reproduce.