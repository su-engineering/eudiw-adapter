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
- **Network policy.** Enabled by default: port 8080 is open, and port 9000 only from the same namespace. Egress is not restricted by the chart. The service needs PostgreSQL, the token issuer, trusted list, status list and CRL locations, and webhook receivers.
- **Configuration changes.** Update the configuration secret and restart the pods. Sessions started under the previous configuration are not served under the new one.
- **HSM keys.** Mount the PKCS#11 library and its configuration with `extraVolumes` and `extraVolumeMounts`, and reference them from the tenant's `verifier.pkcs11` ([ADR-009](adr/0009-hsm-request-signing.md)).
