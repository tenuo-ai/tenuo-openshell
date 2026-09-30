# Tenuo OpenShell Helm chart

This chart deploys the supported HA profile: multiple middleware replicas,
Redis-backed atomic approval replay protection, versioned policy reload,
health probes, persistent revocation rollback floors and receipts, and a
default-deny NetworkPolicy.

Before the first signed release, the default `v0.1.0` image does not exist.
Build the image from a pinned source revision and override both
`image.repository` and `image.tag`. Git releases and images use the same
`vMAJOR.MINOR.PATCH` tag; the Helm chart version omits the `v` as required by
Helm's semantic-version format.

Give every environment and independent deployment its own `replay.keyPrefix`.
The prefix defines the replay namespace: deployments that share it can consume
one another's approval nonces. Only replicas of the same logical deployment
should share a prefix and Redis keyspace.

Before installation, create:

- the policy ConfigMap named by `policy.existingConfigMap`;
- a TLS Secret;
- the OpenShell extension JWT public-key Secret;
- a pre-generated 32-byte receipt signing-key Secret; and
- a Redis URL Secret whose endpoint matches the NetworkPolicy selectors.

For native Redis Cluster, set `replay.cluster=true` and store a comma-separated
list of bootstrap URLs in `replay.redisUrlKey`. Replay keys use one
deployment-specific hash slot so each multi-approval Lua transaction remains
atomic. Standalone Redis remains the default.

The defaults expect `openshell`, `monitoring`, `kube-system`, and `redis`
namespaces. Set caller, admin-scraper, DNS, and Redis selectors to the labels in
your cluster. In particular, distributions that do not label DNS pods
`k8s-app=kube-dns` need selector overrides. For NodeLocal DNSCache, set
`dnsIpBlock` to the cache address as a `/32` (or the appropriate IPv6 CIDR);
that replaces the DNS pod selectors. The schema rejects empty selectors because
they are too broad for the supported production profile. The cluster CNI must
enforce ingress and egress NetworkPolicy.

The admin port is credential-free and exposes health and bounded Prometheus
metrics. NetworkPolicy admits it only from pods matching both
`adminNamespaceSelector` and `adminPodSelector`; Kubernetes node-originated
health probes remain independent of that scraper rule.

The chart requires at least two replicas and uses `maxUnavailable: 1`, so a
voluntary disruption cannot evict more than one middleware replica at a time.

The policy's `revocation.rollback_floor_path` should point under
`/var/lib/tenuo`, which is a per-replica persistent volume. Every policy change
must increment the top-level `version`; invalid or rolled-back updates keep the
last valid policy and increment the reload-failure metric.
