# Performance

These numbers come from one laptop. They show how the cost splits between
local verification, the replay store, and receipts, and roughly how many calls
one replica can decide per second. They are not a guarantee for other
hardware, and the Redis numbers depend mostly on the network round trip to
Redis, which is unusually slow on this machine (see [Redis](#redis-placement)).

Reproduce them with:

```bash
make bench            # or: scripts/bench.sh [--requests N --repeat N ...]
```

The script needs Rust, Docker, and `openssl`. `BENCH_SKIP_REDIS=1` runs only
the scenarios that need no Redis. Results go to `target/bench/`.

## Summary

Release build, gRPC on loopback, receipts off, median of three runs:

| | p50 at 1 caller | p99 at 1 caller | calls/s at 8 callers | calls/s at 64 callers |
| --- | ---: | ---: | ---: | ---: |
| Tool not reserved (idempotent) | 0.18 ms | 0.28 ms | 30,800 | 51,900 |
| Single-use, in-memory store | 0.20 ms | 0.35 ms | 22,400 | 28,200 |
| Single-use, Redis (`redis://`) | 0.76 ms | 1.6 ms | 7,400 | 26,800 |
| Single-use, Redis (`rediss://`) | 0.84 ms | 1.6 ms | 7,000 | 24,100 |
| Production listener (TLS + JWT), Redis | 0.85 ms | 1.6 ms | 7,000 | 23,100 |

A Redis-backed single-use call costs about two Redis round trips more than an
unreserved one: on this machine, 0.18 ms becomes 0.76 ms. Required receipts
add about 0.06 ms to a call at low load and cap one replica at roughly
11,000 to 16,000 calls per second.

## Method

`tenuo-openshell-bench` (`src/bin/tenuo-openshell-bench.rs`) does this for
each configuration:

1. Write a policy with one sandbox, one MCP destination, and one tool,
   `read_logs`. Single-use scenarios list the tool in `single_use_tools`.
2. Start the release `tenuo-openshell-middleware` binary as a child process,
   with the flags for the scenario. Each run gets a fresh process, store key
   prefix, and receipt log.
3. Open one HTTP/2 connection per concurrent caller, as each OpenShell
   supervisor holds its own connection.
4. Sign the calls. Each is a `tools/call` with a 722-byte body: one warrant
   (chain length 1, three constrained arguments) and the holder's proof of
   possession. An `offset` argument differs on every call, so every proof is
   distinct and single-use reservation admits each one. Signing happens before
   the clock starts and is not measured.
5. Send 1,000 warm-up calls, then 10,000 measured calls, at the given
   concurrency. Each caller sends its next call when the previous response
   arrives (closed loop).
6. Record each call's round trip at the client, from send to response. Any
   response other than allow fails the run.

Every configuration runs three times. The tables show the median of each
metric across the three; `max` is the largest single call seen. Throughput is
measured calls divided by wall time.

`tenuo_meta` uses the default, `strip`, so every allowed call also returns a
rewritten body without the proof.

The in-process rows call `evaluate` directly with the same policy, store, and
receipt log, one call at a time. The difference from the gRPC row at one
caller is the cost of the gRPC hop and the server's request handling.

### Scenarios

| Name | Reservation | Store | Listener |
| --- | --- | --- | --- |
| `idempotent` | none | none used | plaintext, no caller auth (`--insecure-dev`) |
| `single-use-memory` | proof reserved and committed | in-process map | plaintext, no caller auth |
| `single-use-redis` | proof reserved and committed | Redis 7.4, `redis://` | plaintext, no caller auth |
| `single-use-rediss` | proof reserved and committed | Redis 7.4, `rediss://`, certificate verified | plaintext, no caller auth |
| `production` | proof reserved and committed | Redis 7.4, `redis://` | TLS and an OpenShell extension JWT checked on every call |

Each scenario runs with receipts off and with receipts on. Receipts on means
`--receipt-key`, `--receipt-log`, and `--require-receipts`: the call is
allowed only after its signed receipt is appended.

### Machine

| | |
| --- | --- |
| CPU | Apple M3 Max, 14 cores (10 performance, 4 efficiency) |
| Memory | 36 GiB |
| OS | macOS 26.5, arm64 |
| Rust | 1.91.1, `--release` profile |
| Redis | 7.4.11 (`redis:7.4-alpine`) in Docker Desktop 29.8.1, no RDB or AOF |
| Redis round trip | `PING` p50 0.26 ms, p99 0.57 ms (Docker Desktop port forwarding) |
| Commit | `745ef60` (main) plus the benchmark |

The client, the middleware, and Redis share the machine. The client runtime
uses 4 threads and the middleware its default runtime. Other work was running
during the measurement: the load average was 16 at the start and 9 at the
end. Single calls, mostly at `max`, are affected by that.

## Results

All times are in microseconds.

### Receipts off

| Scenario | Path | Callers | calls/s | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| idempotent | in-process | 1 | 8,640 | 111 | 140 | 202 | 2,253 |
| idempotent | gRPC | 1 | 5,367 | 177 | 235 | 284 | 1,471 |
| idempotent | gRPC | 8 | 30,755 | 240 | 355 | 484 | 1,375 |
| idempotent | gRPC | 64 | 51,920 | 1,195 | 1,950 | 2,983 | 10,739 |
| single-use-memory | in-process | 1 | 7,383 | 128 | 169 | 223 | 696 |
| single-use-memory | gRPC | 1 | 4,569 | 204 | 277 | 348 | 8,633 |
| single-use-memory | gRPC | 8 | 22,444 | 320 | 597 | 809 | 2,208 |
| single-use-memory | gRPC | 64 | 28,242 | 2,231 | 3,666 | 4,370 | 6,968 |
| single-use-redis | in-process | 1 | 1,361 | 722 | 994 | 1,203 | 6,602 |
| single-use-redis | gRPC | 1 | 1,200 | 763 | 1,195 | 1,631 | 14,254 |
| single-use-redis | gRPC | 8 | 7,380 | 1,056 | 1,370 | 1,583 | 3,895 |
| single-use-redis | gRPC | 64 | 26,841 | 2,322 | 3,083 | 3,894 | 6,589 |
| single-use-rediss | in-process | 1 | 1,130 | 751 | 1,302 | 2,909 | 231,018 |
| single-use-rediss | gRPC | 1 | 1,133 | 836 | 1,195 | 1,565 | 100,918 |
| single-use-rediss | gRPC | 8 | 7,029 | 1,096 | 1,455 | 1,923 | 3,163 |
| single-use-rediss | gRPC | 64 | 24,076 | 2,556 | 3,627 | 4,685 | 133,984 |
| production | gRPC + TLS | 1 | 1,103 | 848 | 1,126 | 1,556 | 110,762 |
| production | gRPC + TLS | 8 | 6,973 | 1,108 | 1,457 | 1,789 | 4,121 |
| production | gRPC + TLS | 64 | 23,122 | 2,694 | 3,709 | 4,889 | 8,490 |

### Receipts on (`--require-receipts`)

| Scenario | Path | Callers | calls/s | p50 | p95 | p99 | max |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| idempotent | in-process | 1 | 5,490 | 170 | 227 | 350 | 8,646 |
| idempotent | gRPC | 1 | 3,655 | 262 | 340 | 444 | 6,626 |
| idempotent | gRPC | 8 | 14,223 | 502 | 799 | 1,791 | 11,233 |
| idempotent | gRPC | 64 | 15,629 | 4,044 | 6,523 | 7,786 | 16,913 |
| single-use-memory | in-process | 1 | 1,993 | 240 | 936 | 3,345 | 111,937 |
| single-use-memory | gRPC | 1 | 1,983 | 300 | 1,087 | 2,648 | 110,350 |
| single-use-memory | gRPC | 8 | 15,326 | 498 | 669 | 821 | 12,969 |
| single-use-memory | gRPC | 64 | 12,946 | 4,630 | 7,796 | 13,891 | 62,316 |
| single-use-redis | in-process | 1 | 1,386 | 688 | 1,002 | 1,258 | 42,760 |
| single-use-redis | gRPC | 1 | 1,232 | 754 | 1,056 | 1,262 | 45,817 |
| single-use-redis | gRPC | 8 | 6,579 | 1,109 | 1,647 | 2,525 | 54,510 |
| single-use-redis | gRPC | 64 | 12,395 | 4,990 | 7,021 | 8,536 | 23,884 |
| single-use-rediss | in-process | 1 | 1,212 | 733 | 1,113 | 1,979 | 285,444 |
| single-use-rediss | gRPC | 1 | 1,318 | 732 | 1,009 | 1,243 | 11,184 |
| single-use-rediss | gRPC | 8 | 7,177 | 1,079 | 1,417 | 1,767 | 7,288 |
| single-use-rediss | gRPC | 64 | 7,933 | 5,629 | 22,806 | 36,636 | 83,043 |
| production | gRPC + TLS | 1 | 1,218 | 791 | 1,033 | 1,255 | 6,777 |
| production | gRPC + TLS | 8 | 6,540 | 1,132 | 1,604 | 2,220 | 10,751 |
| production | gRPC + TLS | 64 | 10,704 | 5,681 | 8,834 | 11,576 | 62,829 |

## Reading the numbers

**Local verification is about 0.11 ms.** Parsing the body, verifying the
warrant chain and the proof, checking constraints, and stripping the proof
take 111 us at p50 in process. The gRPC hop and server handling add about
65 us.

**Redis costs two round trips per single-use call.** A single-use call runs
one script to reserve the proof and a second to commit it. With a 0.26 ms
`PING` round trip, the call goes from 0.18 ms to 0.76 ms at p50, an increase
of 0.59 ms, close to two round trips. TLS to Redis added 0 to 0.07 ms at p50
here; the handshake happens once per connection, not per call.

**Throughput with Redis depends on concurrency.** With 8 callers a replica is
limited by latency: 8 calls in flight at about 1.06 ms each gives 7,400 calls
per second. With 64 callers the round trips overlap on the replica's single
multiplexed Redis connection, and throughput reaches 26,800 calls per second,
close to the in-memory store's 28,200.

**Receipts serialize.** Each allowed call signs a receipt and appends it to
one hash-chained file under a lock. That adds about 60 us per call in
process and limits one replica to roughly 11,000 to 16,000 calls per second
whatever the store. Above that, calls queue: p50 at 64 callers is 4 to 6 ms
with receipts on, against 1.2 to 2.7 ms with them off. The single-use rows
with receipts on show more variance in p95, p99, and max than the others; the
file appends compete with everything else on the machine.

**64 callers is past saturation.** At 64 callers latency is mostly queueing.
For an estimate of the steady state, use the 8-caller rows for latency and
the 64-caller rows for the ceiling.

## Effect of reserving every proof

Pending PR #42 reserves the proof of every tool unless it is listed in
`idempotent_tools`. That code is not on main, so these runs model it on main:
the single-use scenarios list the only tool in `single_use_tools`, which
reserves exactly what #42 would reserve for a tool not marked idempotent. The
`idempotent` scenario is what #42 does for a tool listed in
`idempotent_tools`.

With #42 a production deployment needs Redis, so the relevant comparison is
`idempotent` against `single-use-redis` (receipts off, gRPC):

| | idempotent | single-use, in-memory | single-use, Redis | change, idempotent to Redis |
| --- | ---: | ---: | ---: | ---: |
| p50, 1 caller | 177 us | 204 us | 763 us | +586 us (4.3x) |
| p99, 1 caller | 284 us | 348 us | 1,631 us | +1,347 us |
| calls/s, 8 callers | 30,755 | 22,444 | 7,380 | -76% |
| calls/s, 64 callers | 51,920 | 28,242 | 26,841 | -48% |

With required receipts, which a production deployment would also use, the
gap is smaller because receipts already cap throughput: p50 at 1 caller goes
from 262 us to 754 us, and calls per second at 64 callers from 15,600 to
12,400 (-21%).

So the change is material in relative terms: the replay store becomes most of
the decision time. In absolute terms it is one Redis round trip pair per call,
under 1 ms at p50 here, against OpenShell's 2 s middleware timeout and the
latency of the tool call itself. Marking read-only tools idempotent removes
the cost for those tools.

## What is included and what is not

Included:

- body parsing, warrant chain and proof verification, constraint checks, and
  proof stripping;
- replay reservation and commit, including the Redis round trips;
- receipt signing and append, when on;
- the gRPC call over loopback, HTTP/2 framing, and protobuf encoding;
- for `production`, TLS on the gRPC connections (set up once per connection)
  and verification of the OpenShell JWT on every call.

Not included:

- the network between the OpenShell supervisor and the middleware. Loopback
  has almost no latency; across a node or zone, add that round trip;
- OpenShell's own proxy work: TLS interception, policy evaluation, credential
  injection, and forwarding to the MCP server;
- the MCP tool call itself;
- `--evaluate-results` (result receipts and size limits on responses);
- longer warrant chains, approvals, and signed revocation lists. Each adds
  signature checks; this run uses one warrant without approvals;
- Redis Cluster, Redis persistence (RDB or AOF), and Redis replication;
- signing the calls, which the agent does.

## Redis placement

On a single-use call, Redis latency dominates. The per-call cost is about
0.2 ms of local work plus two Redis round trips, and throughput at moderate
concurrency is calls in flight divided by that.

- Put Redis in the same zone as the middleware replicas, and preferably on
  the same network as their nodes. A same-zone round trip of 0.1 to 0.3 ms
  keeps a single-use call near 0.5 to 0.8 ms. A cross-zone or cross-region
  round trip of several milliseconds is paid twice per call.
- The Docker Desktop round trip here (0.26 ms) is slower than a typical
  same-host or same-zone Linux round trip, so these Redis rows are
  pessimistic for a co-located deployment.
- Use `rediss://`. TLS costs little per call once the connection is open.
- Each replica uses one multiplexed connection to Redis. Throughput keeps
  rising with concurrency because calls share that connection, but a slow
  Redis call delays the calls queued behind it.
- Mark tools that are safe to repeat as idempotent (`idempotent_tools` after
  PR #42) so they skip Redis.

## Known limits

- The in-memory store removes expired entries by scanning the whole map on
  every reservation. It holds each proof for the proof's validity window
  (150 s by default), so the scan grows with the call rate. It is meant for a
  single instance during evaluation; production uses Redis.
- Receipts are appended under one lock, and each append opens the file. That
  is the throughput ceiling with receipts on.
