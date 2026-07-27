# ADR-0002: Fix `llm-shield` Cloud Build Failures — Explicit `.gcloudignore` and Authenticated Private Git Dependencies

**Status:** Partially Implemented
**Date:** 2026-07-27

> **Implementation note (2026-07-27).** Everything in the Implementation Plan is
> committed except step 3: **no Secret Manager secret `github-infra-read` has
> been created**, so the Cloud Build path has not been executed. The project has
> no GitHub token secret today (`npm-token` is an npm credential — it returns
> `401` against the GitHub API), and provisioning one is a credential-ownership
> decision left to a project admin. Until that secret and its
> `roles/secretmanager.secretAccessor` binding exist, `gcloud builds submit`
> will fail at secret resolution. The Dockerfile mechanism itself **is**
> verified — see "Implementation Results" below.

## Context

`gcloud run deploy llm-shield --source=/workspace/agentics-dev/shield --quiet` failed at the "Building Container" step with no actionable output:

```
ERROR: (gcloud.run.deploy) Build failed; check build logs for details
```

`gcloud builds list --project=agentics-dev` showed no builds from that attempt, so the failure was invisible from the CLI. The working hypothesis was a Cloud Build resource or timeout limit, on the theory that `llm-shield` is a large Rust workspace (~58k LOC, 16 crates) that compiles fine locally and in CI.

**That hypothesis is wrong.** Two explicit `gcloud builds submit` runs reproduced the failure with real build IDs and real logs. Neither failure is resource-related — the second one failed **45 seconds** after start (build wall-clock, per `gcloud builds describe`), long before any meaningful compilation.

### Finding 1 — `Cargo.lock` is excluded from the Cloud Build upload

Build `e10d7c4b-2d32-44bf-bca1-0eb0ae634241` (FAILURE):

```
Step 4/34 : COPY Cargo.toml Cargo.lock ./
COPY failed: file not found in build context or excluded by .dockerignore: stat Cargo.lock: file does not exist
```

`Cargo.lock` exists on disk (189 KB) but never reaches Cloud Build. The chain:

1. This repo has **no `.gcloudignore`**.
2. When `.gcloudignore` is absent, `gcloud` derives the upload exclusion set from `.gitignore`.
3. `shield/.gitignore` line 3 is `Cargo.lock`.

Confirmed directly:

```
$ git check-ignore -v Cargo.lock
.gitignore:3:Cargo.lock	Cargo.lock

$ gcloud meta list-files-for-upload | grep -x 'Cargo.lock'
(no output — excluded)
```

`Dockerfile:23` requires it (`COPY Cargo.toml Cargo.lock ./`), so the build dies at step 4/34.

The `.dockerignore` in this repo — which correctly excludes `target/`, `secrets/`, `docs/`, etc. — is **not consulted for the source upload at all**. It only applies once the tarball is already inside Cloud Build. Relying on it for upload hygiene is a category error.

Note also that `Cargo.lock` being gitignored is itself wrong for this repo. `llm-shield` is a deployable binary workspace (`llm-shield-api`); Cargo convention is to commit `Cargo.lock` for binaries so builds are reproducible.

### Finding 2 — private git dependencies cannot be fetched by Cloud Build

With `Cargo.lock` restored to the build context (verified via a staged copy carrying an explicit `.gcloudignore`), build `4037fa71-2902-441a-8c40-565653665139` advanced from step 4/34 to step 22/34 and then failed on the actual `cargo build`:

```
Step 22/34 : RUN cargo build --release --bin llm-shield-api && ...
    Updating crates.io index
    Updating git repository `https://github.com/LLM-Dev-Ops/infra`
error: failed to get `infra-errors` as a dependency of package `llm-shield-core v0.1.1`

Caused by:
  Unable to update https://github.com/LLM-Dev-Ops/infra?branch=main#a8bc89c1
Caused by:
  revision a8bc89c190f63b139812f30a54e21a25b8f70e81 not found
Caused by:
  failed to authenticate when downloading repository
  * attempted to find username/password via git's `credential.helper` support, but failed
Caused by:
  failed to acquire username/password from local configuration
returned a non-zero code: 101
```

Total build wall-clock: **45 seconds** (`21:30:09Z` → `21:30:54Z`). `Cargo.toml` declares 16 workspace dependencies pointing at `https://github.com/LLM-Dev-Ops/infra`, plus `policy-engine` and `config-manager`. Repository visibility:

```
LLM-Dev-Ops/infra              404   <- private (or absent)
LLM-Dev-Ops/policy-engine      200
LLM-Dev-Ops/config-manager     200
```

`LLM-Dev-Ops/infra` is not publicly readable. Cloud Build's worker has no GitHub credentials and no `credential.helper`, so cargo cannot clone it. This is exactly why local agent sessions and GitHub Actions succeed while Cloud Build fails: developer machines have a configured git credential helper or SSH agent, and CI runs with `secrets.GITHUB_TOKEN` scoped to the org. Neither is present in Cloud Build.

### Finding 3 — resource limits are ruled out, not merely unlikely

Neither failure resembles OOM, disk exhaustion, or timeout. Both terminated within a minute of the build starting, with explicit, unambiguous errors. No `cloudbuild.yaml` exists at the root of this repo (only an unrelated `agents/cloudbuild.yaml`), so the default machine type is in use — but the default machine type is not what is breaking these builds. Machine sizing is currently an **unmeasured** variable, because the build has never reached sustained compilation.

### Finding 4 (incidental, security hygiene) — `secrets/` is uploaded to Cloud Build

Because the upload ignore-set is derived from `.gitignore` (which does not list `secrets/`) rather than `.dockerignore` (which does), the source tarball pushed to `gs://agentics-dev_cloudbuild/source/` includes:

```
secrets/api_keys.txt
secrets/README.md
```

The current `secrets/api_keys.txt` appears to be a comment-only template, so this is not a live disclosure. It is still a latent leak path: any real key dropped there would be silently copied into a GCS bucket on the next deploy. An explicit `.gcloudignore` fixes this as a side effect.

### Finding 5 (discovered during implementation) — the builder base image has too old a glibc

Once Findings 1 and 2 were fixed, a full build got all the way to linking the
final binary and failed there:

```
rust-lld: error: undefined symbol: __isoc23_strtoull
  >>> referenced by resource_accountant.cc ... in archive libort_sys-*.rlib
rust-lld: error: undefined symbol: __isoc23_strtoll
rust-lld: error: undefined symbol: __isoc23_strtol
error: could not compile `llm-shield-api` (bin "llm-shield-api")
```

The `ort` crate does not compile ONNX Runtime from source; it downloads a
**prebuilt** static library (visible in the link line as
`-L /root/.cache/ort.pyke.io/dfbin/x86_64-unknown-linux-gnu/...`). That prebuilt
artifact was compiled against glibc ≥ 2.38, which is where `__isoc23_strtol`,
`__isoc23_strtoll` and `__isoc23_strtoull` were introduced.
`rust:1.93-slim-bookworm` is Debian 12, glibc **2.36**:

```
bookworm: ldd (Debian GLIBC 2.36-9+deb12u13) 2.36
trixie:   ldd (Debian GLIBC 2.41-12+deb13u1) 2.41
```

So the symbols are simply absent. This is a third, independent defect — nothing
to do with the upload set or with credentials — and it would fail identically in
Cloud Build, which uses the same Dockerfile. The fix is to move the builder to
`rust:1.93-slim-trixie` and the runtime stage to `gcr.io/distroless/cc-debian13`
so the binary's glibc requirement matches its runtime base.

## Decision

1. **Add an explicit `.gcloudignore` to the repository root.** Never let `gcloud` derive the upload set from `.gitignore`. The two files answer different questions — `.gitignore` means "do not version this", `.gcloudignore` means "do not ship this to the builder" — and `Cargo.lock` is the case where those answers diverge and break the build.
2. **Stop gitignoring `Cargo.lock` and commit it.** `llm-shield` ships a binary; a committed lockfile is required for reproducible container builds.
3. **Supply GitHub credentials to the Cloud Build worker via Secret Manager**, injected as a BuildKit build secret and consumed through a `git config --global url.<...>.insteadOf` rewrite so cargo can clone `LLM-Dev-Ops/infra`. The token must never be written into an image layer.
4. **Add a root `cloudbuild.yaml`** as the single declared build entrypoint, so the build is reproducible and reviewable rather than implicit in whatever `gcloud run deploy --source` happens to do. Set `timeout: 2700s` and **no `machineType` override** — keep the default machine. During this investigation the sibling `llm-orchestrator` repo (10 crates, ~44k LOC) built cold, end to end, in **7m44s on the default Cloud Build machine** with no caching (see ADR-0003 Finding 2). `llm-shield` is larger, but not so much larger that the default machine is presumptively inadequate, and it additionally *has* a dependency-caching layer (`Dockerfile:23-62`) that orchestrator lacks. Measure first; only add `machineType: E2_HIGHCPU_8` if a real build time justifies the spend.
5. **Move the build and runtime bases to Debian 13** (`rust:1.93-slim-trixie` and `gcr.io/distroless/cc-debian13`), and add `git` to the builder's `apt-get install` list. Required by Finding 5; `rust:slim` does not ship `git`, which the `insteadOf` rewrite needs.
6. **Deprecate `gcloud run deploy --source` for this repo.** Build with `gcloud builds submit --config=cloudbuild.yaml`, then deploy the resulting tagged image with `gcloud run deploy --image=...`. The `--source` path swallows build IDs and log URLs, which is what made this failure take a full night to diagnose.

The equivalent decision for `llm-orchestrator` is recorded in `orchestrator/docs/adr/ADR-0003`. The two repos share the root-cause *class* (the `.gcloudignore` / `.gitignore` distinction) but have different concrete defects and different fixes; neither is a resource problem.

## Consequences

**Positive**

- Builds fail with real, greppable errors instead of `Build failed; check build logs for details`.
- `secrets/` and `target/` stop being uploaded to GCS on every build.
- Committing `Cargo.lock` makes container builds byte-reproducible and closes a class of "works locally, breaks in prod" drift.
- An explicit `cloudbuild.yaml` becomes the place where future build config (caching, machine size, substitutions) lives, reviewable in PRs.

**Negative / costs**

- A GitHub token with read access to `LLM-Dev-Ops/infra` must be provisioned, stored in Secret Manager, and rotated. This is new credential surface that did not previously exist in GCP.
- The Cloud Build service account needs `roles/secretmanager.secretAccessor`, a permission grant that requires project-admin action.
- Deploys become two commands instead of one. This is a deliberate trade of convenience for diagnosability.

**Risks**

- ~~The pinned revision `a8bc89c190f63b139812f30a54e21a25b8f70e81` was also reported "not found".~~ **Resolved.** The revision exists (`GET /repos/LLM-Dev-Ops/infra/commits/a8bc89c1…` returns it). The "not found" was purely a consequence of the failed clone, as suspected; the pin is not stale.
- The long-term fix for a 16-way private git dependency is to publish those crates to a private registry (Artifact Registry supports Cargo). Token-based git cloning is the pragmatic fix, not the durable one.

## Implementation Plan

1. **Create `shield/.gcloudignore`** at the repository root. **Every top-level exclusion must be anchored with a leading `/`.** `.gcloudignore` uses gitignore matching semantics, so an unanchored `benchmarks/` matches a directory of that name at *any* depth and will silently delete Rust source from the build context. This repo has three such collisions:

   ```
   crates/llm-shield-benchmarks/src/benchmarks/
   crates/llm-shield-api/src/models/
   crates/llm-shield-dashboard/src/models/
   ```

   An unanchored `benchmarks/` or `models/` pattern strips those and produces `error[E0583]: file not found for module ...` — a compile error that looks like a source bug but is an upload bug. This failure mode was reproduced during this investigation (see the `llm-orchestrator` ADR-0003 Finding 3). Use:

   ```
   # Upload exclusions for `gcloud builds submit` / `gcloud run deploy --source`.
   #
   # NOTE 1: this file overrides the .gitignore-derived default. Cargo.lock is
   #         gitignored but MUST be uploaded — the Dockerfile COPYs it.
   # NOTE 2: leading "/" anchors each pattern to the repo root. Do NOT drop it:
   #         an unanchored "benchmarks/" or "models/" also matches
   #         crates/*/src/benchmarks/ and crates/*/src/models/ and will break
   #         the build with a misleading E0583 compile error.
   .git/
   .github/
   /target/
   **/target/
   **/node_modules/
   /secrets/
   /models/
   /packages/
   /agents/
   /benchmarks/
   /examples/
   /monitoring/
   /plans/
   /docs/
   *.log
   .env
   .env.*
   ```

2. **Remove `Cargo.lock` from `shield/.gitignore`** (delete line 3) and commit the existing `Cargo.lock`.

3. **Provision the GitHub token.** Create a fine-grained PAT (or GitHub App installation token) with `Contents: read` on `LLM-Dev-Ops/infra`, then:

   ```bash
   printf '%s' "$GH_TOKEN" | gcloud secrets create github-infra-read \
     --project=agentics-dev --data-file=-

   PROJECT_NUM=1062287243982
   gcloud secrets add-iam-policy-binding github-infra-read \
     --project=agentics-dev \
     --member="serviceAccount:${PROJECT_NUM}@cloudbuild.gserviceaccount.com" \
     --role=roles/secretmanager.secretAccessor
   ```

4. **Modify `shield/Dockerfile`** to consume the token as a BuildKit secret. Replace the two `cargo build --release` invocations (currently lines 62 and 70) with mounted-secret forms, and add the credential rewrite. The token is only ever present inside the `RUN` mount and never lands in a layer:

   `rust:1.93-slim-bookworm` does **not** ship `git` (verified: `which git` →
   absent), so `git` must be added to the existing `apt-get install` list or the
   `git config` below fails with `git: not found`.

   ```dockerfile
   # syntax=docker/dockerfile:1.7
   ...
   RUN --mount=type=secret,id=gh_token \
       git config --global \
         url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf \
         "https://github.com/" && \
       cargo build --release --bin llm-shield-api && \
       rm -rf target/release/deps/llm_shield* target/release/deps/llm_security* \
              target/release/deps/libllm_shield* target/release/deps/libllm_security* && \
       git config --global --unset-all url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf
   ```

   Apply the same `--mount=type=secret,id=gh_token` and `insteadOf` rewrite to the second `cargo build --release --bin llm-shield-api` (Dockerfile line 70).

5. **Create `shield/cloudbuild.yaml`**:

   ```yaml
   # No machineType override: the sibling llm-orchestrator workspace builds
   # cold in ~7m44s on the default machine (ADR-0003 Finding 2). Add one only
   # if a measured build time here justifies the cost.
   timeout: 2700s

   options:
     logging: CLOUD_LOGGING_ONLY

   availableSecrets:
     secretManager:
       - versionName: projects/agentics-dev/secrets/github-infra-read/versions/latest
         env: GH_TOKEN

   steps:
     - id: build
       name: gcr.io/cloud-builders/docker
       entrypoint: bash
       secretEnv: ['GH_TOKEN']
       args:
         - -c
         - |
           set -euo pipefail
           printf '%s' "$$GH_TOKEN" > /workspace/gh_token
           DOCKER_BUILDKIT=1 docker build \
             --secret id=gh_token,src=/workspace/gh_token \
             -t "$_IMAGE:$SHORT_SHA" \
             -t "$_IMAGE:latest" \
             .
           rm -f /workspace/gh_token

   substitutions:
     _IMAGE: us-central1-docker.pkg.dev/agentics-dev/cloud-run-source-deploy/llm-shield

   images:
     - '$_IMAGE:$SHORT_SHA'
     - '$_IMAGE:latest'
   ```

6. **Confirm the upload set is correct before spending a build**, which is free and instant:

   ```bash
   cd shield
   gcloud meta list-files-for-upload | grep -xE 'Cargo.lock|Cargo.toml|Dockerfile'
   gcloud meta list-files-for-upload | grep -c '^secrets/'                        # must be 0
   gcloud meta list-files-for-upload | grep -c '^target/'                         # must be 0
   gcloud meta list-files-for-upload | grep -c 'llm-shield-benchmarks/src/'       # must be > 0
   gcloud meta list-files-for-upload | grep -c 'llm-shield-api/src/models/'       # must be > 0
   ```

   The last two guard against the anchoring trap: they confirm nested `benchmarks/` and `models/` source directories survived the ignore rules.

7. **Update the deploy runbook** to the two-step flow, replacing `gcloud run deploy --source`:

   ```bash
   gcloud builds submit --project=agentics-dev --config=cloudbuild.yaml .
   gcloud run deploy llm-shield --project=agentics-dev --region=us-central1 \
     --image=us-central1-docker.pkg.dev/agentics-dev/cloud-run-source-deploy/llm-shield:latest
   ```

8. **Open a follow-up issue** to migrate the `LLM-Dev-Ops/infra` crates to Artifact Registry as a private Cargo registry, retiring the git-dependency-plus-token arrangement.

## Verification

The fix is verified when all of the following hold:

1. **Upload set (pre-build, instant).** `gcloud meta list-files-for-upload` in `shield/` lists `Cargo.lock`, `Cargo.toml`, and `Dockerfile`; matches zero paths under `secrets/` or `target/`; and still matches files under `crates/llm-shield-benchmarks/src/` and `crates/llm-shield-api/src/models/` (proving the ignore patterns are anchored and did not strip nested source).

2. **Step 4/34 passes.** A `gcloud builds submit --config=cloudbuild.yaml` run gets past `COPY Cargo.toml Cargo.lock ./` without `COPY failed: ... stat Cargo.lock: file does not exist`. This is the direct regression test for Finding 1.

3. **Dependency resolution succeeds.** Build logs show `Updating git repository https://github.com/LLM-Dev-Ops/infra` followed by compilation, with no `failed to authenticate when downloading repository`. This is the regression test for Finding 2. Baseline to beat: the current build dies here at **45 seconds**.

4. **Build completes.** Status `SUCCESS` with an image pushed to `us-central1-docker.pkg.dev/agentics-dev/cloud-run-source-deploy/llm-shield`. Record the wall-clock duration:

   ```bash
   gcloud builds list --project=agentics-dev --limit=1 \
     --format='table(id,status,duration)'
   ```

   Reference point: the sibling `llm-orchestrator` workspace (10 crates, no caching) built cold in **7m44s on the default machine**. `llm-shield` is roughly 60% larger but has a dependency-caching layer, so a cold build in the 10–25 minute range on the default machine is the expectation, well inside the 2700s timeout. **Record the actual number — it is currently unmeasured, because no shield build has ever reached sustained compilation.** Only if it exceeds ~35 minutes should `machineType: E2_HIGHCPU_8` be added, and even then re-measure rather than assuming it helped.

5. **No token in the image.** The built image must not contain the credential.

   Note the check originally drafted here — `docker history | grep -i
   'x-access-token'` — is a **false positive by construction**: the literal
   string `x-access-token` is part of the `RUN` instruction text and is always
   recorded in the image history. What matters is that the *value* never
   appears. `$(cat /run/secrets/gh_token)` is recorded unexpanded, so grep for
   the token itself:

   ```bash
   TOK=$(gcloud secrets versions access latest --secret=github-infra-read --project=agentics-dev)
   docker history --no-trunc <image> | grep -cF "$TOK"   # must be 0
   docker inspect <image>            | grep -cF "$TOK"   # must be 0
   docker run --rm --entrypoint sh -e TOK="$TOK" <image> \
     -c 'grep -rlF "$TOK" /root /etc/gitconfig /usr/local/cargo 2>/dev/null | wc -l'  # must be 0
   ```

6. **Deploy is not part of this verification.** Building the image proves the build is fixed. Promoting it to the live `llm-shield` Cloud Run service is a separate, explicitly-authorized step.

## Implementation Results (2026-07-27)

What was verified for real, and what was not.

**Verified — upload set (criterion 1).** With the new `.gcloudignore`,
`gcloud meta list-files-for-upload` yields 295 files:

| Check | Required | Actual |
|---|---|---|
| `Cargo.lock`, `Cargo.toml`, `Dockerfile`, `cloudbuild.yaml` | present | present |
| `secrets/` | 0 | 0 |
| `target/` | 0 | 0 |
| `docs/` | 0 | 0 |
| root `models/` | 0 | 0 |
| `llm-shield-benchmarks/src/` | > 0 | 8 |
| `llm-shield-api/src/models/` | > 0 | 5 |
| `llm-shield-dashboard/src/models/` | > 0 | 1 |

All 16 crate manifests the Dockerfile `COPY`s are present, along with 207 Rust
source files. The anchoring trap was avoided.

**Verified — criteria 2, 3, 4 and 5, via a local BuildKit build.** No Secret
Manager secret exists yet (see the note at the top), so Cloud Build could not be
exercised. Instead the identical Dockerfile was built locally with the same
`--secret id=gh_token` mechanism the `cloudbuild.yaml` step uses:

- `COPY Cargo.toml Cargo.lock ./` **passes** — Finding 1 fixed.
- `Updating git repository https://github.com/LLM-Dev-Ops/infra` **succeeds**,
  with no `failed to authenticate` — Finding 2 fixed. Worth recording: cargo's
  default libgit2 backend *does* honour `url.<...>.insteadOf` here, so
  `net.git-fetch-with-cli` is not required.
- The workspace **builds end to end** and produces a 72.3 MB image. This is the
  first time an `llm-shield` container build has ever completed.
- **Wall clock: 6m25s** (385s) cold, no cache, on a local machine. Cloud Build's
  default machine will differ, but this is comfortably inside `timeout: 2700s`
  and gives no reason to add a `machineType` override.
- **No token in the image**: 0 occurrences of the token value in
  `docker history --no-trunc`, in `docker inspect`, and in a filesystem scan of
  `/root`, `/etc/gitconfig` and `/usr/local/cargo`. `/root/.gitconfig` is empty
  and `/run/secrets` does not exist in the image.

**Not verified — the Cloud Build path itself.** `gcloud builds submit
--config=cloudbuild.yaml` has not been run, because
`projects/agentics-dev/secrets/github-infra-read` does not exist. Implementation
Plan step 3 is the remaining work. Once that secret and its
`roles/secretmanager.secretAccessor` binding are in place, the config here is
expected to work unchanged, but that expectation is untested.
