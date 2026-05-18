# @jentz swamp extensions

Generic [swamp](https://swamp-club.com) extensions for AWS audit and
read-only-recon workflows. Each subdirectory is a self-contained publishable
package with its own manifest, source, tests, and README.

## Extensions

| Extension                                            | Type   | Purpose                                                                                                                                     |
| ---------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| [`@jentz/aws-context-guard`](aws-context-guard/)     | model  | Workflow-safety primitive. Fails closed before any AWS work runs by verifying `AWS_PROFILE` suffix and `sts:GetCallerIdentity` account ID.  |
| [`@jentz/aws-s3-bucket-audit`](aws-s3-bucket-audit/) | report | Workflow-scope report that audits S3 buckets against standard security best practices. Emits markdown + JSON with a `failOn` severity gate. |

## Installation

Per-extension via the swamp registry:

```sh
swamp extension pull @jentz/aws-context-guard
swamp extension pull @jentz/aws-s3-bucket-audit
```

## Development

The repo is a swamp repository in its own right (`.swamp.yaml` at the root).
Tests run under the swamp-bundled Deno so versions and resolver behavior match
what `swamp extension push` uses:

```sh
~/.swamp/deno/deno test --allow-read --allow-env --allow-net --no-check \
  aws-context-guard/tests/ aws-s3-bucket-audit/tests/
```

Each manifest opts in to `paths.base: manifest` so per-extension subdirectories
are self-contained: manifest, source, README, and LICENSE all sit alongside each
other.

To validate a manifest and produce a publishable tarball locally without
uploading:

```sh
swamp extension fmt aws-context-guard/manifest.yaml --check
swamp extension quality aws-context-guard/manifest.yaml
swamp extension push aws-context-guard/manifest.yaml --dry-run
```

## Issues

Bug reports, feature requests, and security disclosures for either extension go
to GitHub Issues: <https://github.com/jentz/swamp-extensions/issues>

## Versioning

Each extension publishes independently on its own CalVer timeline
(`YYYY.MM.DD.MICRO`). The list of breaking-change rules is documented in each
extension's README.

## License

MIT — see [LICENSE](LICENSE).
