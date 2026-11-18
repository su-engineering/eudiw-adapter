# Kubernetes

The Helm chart in [`deploy/helm/eudiw-adapter`](../deploy/helm/eudiw-adapter) runs the verifier service under the restricted Pod Security Standard:
- non-root user 10001 with a read-only root filesystem;
- all capabilities dropped and the `RuntimeDefault` seccomp profile;
- no service account token;
- probes on the management port.

CI installs it into a kind cluster with that standard enforced, runs two replicas against PostgreSQL, and starts a session through the API ([smoke test](../deploy/helm/smoke-test.sh)).

## Image and chart

Each release publishes, from the [release workflow](../.github/workflows/release.yaml):
- the image `ghcr.io/su-engineering/eudiw-adapter:<version>` for `linux/amd64` and `linux/arm64`, signed with cosign (keyless, GitHub OIDC), with an SBOM and build provenance attached in the registry;
- the chart `oci://ghcr.io/su-engineering/charts/eudiw-adapter`, also signed, and as a `.tgz` on the GitHub release;
- an SPDX SBOM of the image on the GitHub release.

Verify the image before deploying it:

```bash
cosign verify ghcr.io/su-engineering/eudiw-adapter:0.2.1 \
  --certificate-identity https://github.com/su-engineering/eudiw-adapter/.github/workflows/release.yaml@refs/tags/v0.2.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The chart uses the image matching its `appVersion` unless you set `image.tag`. To pin the digest cosign verified, set `image.tag` to `0.2.1@sha256:<digest>`.

To build the image yourself instead:

```bash
./mvnw -pl adapter-verifier-service -am package -DskipTests
docker build -t registry.example/eudiw-adapter:0.2.1 -f adapter-verifier-service/src/main/docker/Dockerfile .
```

and set `image.repository` and `image.tag`.

## Install

Create three secrets in the release namespace:

| Secret | Keys | Content |
| --- | --- | --- |
| database | `username`, `password` | PostgreSQL 16 or later credentials |
| data key | `data-key`, optionally `previous-data-keys` | `openssl rand -base64 32`; old keys during a [rotation](configuration.md#rotating-the-data-key), comma-separated |
| configuration | `tenants.json` and every file it references | Mounted read-only at `/config`; paths in `tenants.json` are relative to it ([configuration](configuration.md)) |

```bash
helm install eudiw oci://ghcr.io/su-engineering/charts/eudiw-adapter --version 0.2.1 -n eudiw \
  --set publicBaseUrl=https://adapter.example \
  --set oidc.issuer=https://auth.example/realms/main --set oidc.audience=eudiw-adapter \
  --set database.url=jdbc:postgresql://postgres:5432/eudiw --set database.existingSecret=eudiw-db \
  --set dataKey.existingSecret=eudiw-data-key --set config.existingSecret=eudiw-config
```

Expose the Service's port 8080 over HTTPS at `publicBaseUrl`, for example with your ingress controller. Do not expose port 9000.

## Operation

- **Replicas.** Any number of replicas can run. Session completion, webhook delivery and trusted list sequence numbers are coordinated in PostgreSQL. Each replica refreshes trusted lists itself.
- **Network policy.** Enabled by default: port 8080 is open, and port 9000 only from the same namespace and the namespaces `networkPolicy.managementNamespaceSelector` selects.
- **Egress policy.** Set `networkPolicy.egress.enabled` in production. The pod may then reach cluster DNS, the in-cluster destinations you list in `networkPolicy.egress.cluster` (PostgreSQL, an in-cluster token issuer or webhook receiver), and public addresses on `networkPolicy.egress.internetPorts` (443 and 80). Private, loopback, link-local (cloud metadata), carrier-grade NAT and IPv6 transition ranges are refused. The service checks every list, status and CRL address itself, but DNS can change between that check and the connection; this policy closes that gap. It needs a CNI that enforces NetworkPolicy. For example, with PostgreSQL in namespace `eudiw-db`:

  ```yaml
  networkPolicy:
    egress:
      enabled: true
      cluster:
        - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: eudiw-db}}}]
          ports: [{port: 5432, protocol: TCP}]
  ```

  To fetch lists, status lists and CRLs only from known hosts, also set `egress.allowedHosts` (`EUDIW_EGRESS_ALLOWED_HOSTS`, see [configuration](configuration.md)). To send those fetches through a forward proxy instead of straight to the internet, set `egress.proxy` (`EUDIW_EGRESS_PROXY`) and allow the proxy in `networkPolicy.egress.cluster`; you can then set `networkPolicy.egress.internetPorts` to `[]`. In an IPv6-only cluster with DNS64, IPv4-only hosts appear under the NAT64 prefix `64:ff9b::/96`. The service accepts such an address when the IPv4 address it embeds is public, but the chart's IPv6 rule covers only `2000::/3`, so add a `cluster` rule for `64:ff9b::/96` on the internet ports.
- **Configuration changes.** Update the configuration secret. Each pod picks it up within `configReload.interval` (30 seconds by default), keeps the previous configuration for open sessions, and keeps running on the old one if the new one does not validate ([Reloading](configuration.md#reloading)). Kubernetes updates mounted Secrets after a short delay, so pods can briefly serve different revisions; a session that reaches a pod without its revision makes that pod check for the new file first.
- **Metrics.** `:9000/metrics` in Prometheus format. Set `metrics.serviceMonitor.enabled` for the Prometheus Operator, and `networkPolicy.managementNamespaceSelector` so the scraper's namespace can reach port 9000. Alert on `eudiw_trusted_lists_current == 0`, `eudiw_registration_certificate_expiry_seconds < 2592000` and `rate(eudiw_config_reloads_total{outcome="failed"}[5m]) > 0`.
- **Event streams.** `/v1/verification-sessions/{id}/events` keeps a connection open for up to the session lifetime (15 minutes by default) and sends a comment every 15 seconds. Ingress and load balancer idle timeouts must be longer than that, and response buffering must be off for this path; with ingress-nginx, `nginx.ingress.kubernetes.io/proxy-buffering: "off"` and `proxy-read-timeout` above 15. A stream ends when its pod stops; clients reconnect and get the current status first ([ADR-013](adr/0013-session-events.md)).
- **Tracing.** Set `tracing.enabled` and `tracing.endpoint` (an OTLP collector).
- **Vault Transit keys.** Let Vault Agent (the injector or a sidecar) write the token to a shared volume, and point the tenant's `verifier.vault_transit.token_file` at it. The adapter reads the file on every signature, so renewals need no restart ([ADR-014](adr/0014-remote-request-signing.md)).
- **HSM keys.** Mount the PKCS#11 library and its configuration with `extraVolumes` and `extraVolumeMounts`, and reference them from the tenant's `verifier.pkcs11` ([ADR-009](adr/0009-hsm-request-signing.md)). The image is glibc based, so vendor libraries built for glibc load.
