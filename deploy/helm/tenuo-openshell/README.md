# Tenuo OpenShell Helm chart

This chart deploys the supported HA profile: multiple middleware replicas,
Redis-backed atomic approval replay protection, versioned policy reload,
health probes, persistent revocation rollback floors and receipts, and a
default-deny NetworkPolicy.

Give each environment a distinct `replay.keyPrefix`. Sharing a prefix across
clusters is safe but can cause one deployment to consume another deployment's
approval nonce.

Before installation, create:

- the policy ConfigMap named by `policy.existingConfigMap`;
- a TLS Secret;
- the OpenShell extension JWT public-key Secret;
- a pre-generated 32-byte receipt signing-key Secret; and
- a Redis URL Secret whose endpoint matches the NetworkPolicy selectors.

The defaults expect `openshell` and `redis` namespaces. Set caller and Redis
namespace/pod selectors to the labels in your cluster. Empty selectors are
valid Kubernetes selectors but intentionally broad and unsuitable for a
production values file. The cluster CNI must enforce ingress and egress
NetworkPolicy.

The policy's `revocation.rollback_floor_path` should point under
`/var/lib/tenuo`, which is a per-replica persistent volume. Every policy change
must increment the top-level `version`; invalid or rolled-back updates keep the
last valid policy and increment the reload-failure metric.
