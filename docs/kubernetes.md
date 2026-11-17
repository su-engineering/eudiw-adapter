# Kubernetes

The Helm chart in [`deploy/helm/eudiw-adapter`](../deploy/helm/eudiw-adapter) runs the verifier service under the restricted Pod Security Standard:
- non-root user 10001 with a read-only root filesystem;
- all capabilities dropped and the `RuntimeDefault` seccomp profile;
- no service account token;
- probes on the management port.

CI installs it into a kind cluster with that standard enforced, runs two replicas against PostgreSQL, and starts a session through the API ([smoke test](../deploy/helm/smoke-test.sh)).

## Image

No image is published yet. Build one from a checkout and push it to your own registry:

```bash
./mvnw -pl adapter-verifier-service -am package -DskipTests
docker build -t registry.example/eudiw-adapter:0.1.0 -f adapter-verifier-service/src/main/docker/Dockerfile .
```

## Install

Create three secrets in the release namespace:

| Secret | Keys | Content |
| --- | --- | --- |
| database | `username`, `password` | PostgreSQL 16 or later credentials |
| data key | `data-key` | `openssl rand -base64 32` |
| configuration | `tenants.json` and every file it references | Mounted read-only at `/config`; paths in `tenants.json` are relative to it ([configuration](configuration.md)) |

```bash
helm install eudiw deploy/helm/eudiw-adapter -n eudiw \
  --set image.repository=registry.example/eudiw-adapter --set image.tag=0.1.0 \
  --set publicBaseUrl=https://adapter.example \
  --set oidc.issuer=https://auth.example/realms/main --set oidc.audience=eudiw-adapter \
  --set database.url=jdbc:postgresql://postgres:5432/eudiw --set database.existingSecret=eudiw-db \
  --set dataKey.existingSecret=eudiw-data-key --set config.existingSecret=eudiw-config
```

Expose the Service's port 8080 over HTTPS at `publicBaseUrl`, for example with your ingress controller. Do not expose port 9000.

## Operation

- **Replicas.** Any number of replicas can run. Session completion, webhook delivery and trusted list sequence numbers are coordinated in PostgreSQL. Each replica refreshes trusted lists itself.
- **Network policy.** Enabled by default: port 8080 is open, and port 9000 only from the same namespace and the namespaces `networkPolicy.managementNamespaceSelector` selects. Egress is not restricted by the chart. The service needs PostgreSQL, the token issuer, trusted list, status list and CRL locations, and webhook receivers.
- **Configuration changes.** Update the configuration secret. Each pod picks it up within `configReload.interval` (30 seconds by default), keeps the previous configuration for open sessions, and keeps running on the old one if the new one does not validate ([Reloading](configuration.md#reloading)). Kubernetes updates mounted Secrets after a short delay, so pods can briefly serve different revisions; a session that reaches a pod without its revision makes that pod check for the new file first.
- **Metrics.** `:9000/metrics` in Prometheus format. Set `metrics.serviceMonitor.enabled` for the Prometheus Operator, and `networkPolicy.managementNamespaceSelector` so the scraper's namespace can reach port 9000. Alert on `eudiw_trusted_lists_current == 0`, `eudiw_registration_certificate_expiry_seconds < 2592000` and `rate(eudiw_config_reloads_total{outcome="failed"}[5m]) > 0`.
- **Tracing.** Set `tracing.enabled` and `tracing.endpoint` (an OTLP collector).
- **HSM keys.** Mount the PKCS#11 library and its configuration with `extraVolumes` and `extraVolumeMounts`, and reference them from the tenant's `verifier.pkcs11` ([ADR-009](adr/0009-hsm-request-signing.md)). The image is glibc based, so vendor libraries built for glibc load.
