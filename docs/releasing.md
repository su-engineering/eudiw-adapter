# Releasing

1. On a branch, set the version in Maven (`./mvnw versions:set -DnewVersion=X.Y.Z -DgenerateBackupPoms=false -DprocessAllModules`), in `deploy/helm/eudiw-adapter/Chart.yaml` (`version` and `appVersion`) and in `clients/web/package.json`, and add a `## [X.Y.Z]` section to `CHANGELOG.md`. Merge it once CI passes.
2. Tag the merge commit and push the tag: `git tag -a vX.Y.Z -m "eudiw-adapter X.Y.Z" && git push origin vX.Y.Z`.
3. The [release workflow](../.github/workflows/release.yaml) runs the whole of CI, checks that every version matches the tag, then publishes the signed image, the signed chart and the GitHub release, and stages the npm package with provenance.
4. Approve the staged npm version with 2FA: on npmjs.com, or with `npm stage list @su-engineering/eudiw-request` and `npm stage approve <stage-id>`. npm then runs its automated review for a few minutes before the version is installable.
5. Point the quickstart at the new image: set the tag and the image's digest (`docker buildx imagetools inspect ghcr.io/su-engineering/eudiw-adapter:<version>`) in `deploy/quickstart/docker-compose.yml`, and add any policy settings the release introduced to `deploy/quickstart/tenants.json` only once the released image understands them. CI's `quickstart` job runs it.
6. Set the Maven version on `main` to the next `-SNAPSHOT`. The chart and the npm package keep the released version until the next release, so the chart on `main` always points at a published image.
