---
name: land
description: >-
  Land explicitly requested griffin-mail changes by committing and merging them
  into main in the primary local checkout. Invoke only when the user requests
  landing or merging, including an explicit /land invocation, never merely for
  review, preparation, passing checks, or skill installation.
disable-model-invocation: true
metadata:
  delta-action: land
---

# Land locally

## Scope and intent

Carry out the requested landing through verification of the primary local
checkout's `main` branch. An explicit invocation supplies permission to land;
do not ask again whether to merge. Stop only for a genuine blocker, unclear
scope, or a workspace permission gate.

This workflow applies only to griffin-mail. The investigated primary checkout
was `/home/matt/git/rust/griffin-mail`, linked by the `local` Git remote. Resolve
the current `local` remote rather than assuming that path on another machine.
The destination is local `main`, not `origin/main`. Never push to a remote,
open a pull request, deploy, release, force-update refs, or rewrite history.

## Preflight and change preparation

1. Read applicable repository instructions and any current contribution or
   landing policy. At installation there was no contribution policy, CI
   workflow, or existing landing implementation. Honor subsequently added
   requirements, including conditional review, signing, authorship, tests,
   documentation, or submission requirements. Do not invent remote checks or
   reviews for this local-only workflow.
2. Inspect remotes, current branch, status, staged and unstaged diffs, and
   relevant history using read-only Git commands. Resolve the `local` remote's
   Git directory to its primary working checkout; inspect that checkout's
   current branch and status. Confirm the requested changes and destination
   are unambiguous. Do not treat the thread's own checkout as the primary
   checkout merely because both have a branch named `main`.
3. Before writing to a primary checkout outside the attached workspace, require
   it to be attached or obtain explicit authorization for direct edits there.
   The landing request alone is not a substitute for this workspace gate.
   Do not bypass it by updating its refs through a push to `local`.
4. Preserve unrelated changes, staged files, and untracked files in both
   checkouts. Never automatically stash, delete, overwrite, or include them
   in the landing commit. Disjoint untracked files can remain; check for path
   collisions. Require unrelated tracked edits to be dealt with by their owner
   when they would make committing, switching, or merging unsafe. Stop and ask
   one focused question if ownership or scope is uncertain.
5. Work on a uniquely named temporary topic branch in the source workspace,
   rather than moving its `main` prematurely. Record the original branch and
   destination commit. Stage only the requested paths or hunks, inspect the
   staged diff, and commit with a concise descriptive subject and explicit
   message. Preserve existing commits if the change is already committed;
   do not squash or amend them. Follow configured signing and identity rules;
   if credentials or signing are unavailable, stop rather than bypassing them.
   Prefix Git commands that might invoke an editor with `GIT_EDITOR=true` and
   supply messages explicitly. Never use interactive rebase.
6. Fetch the destination branch from the local filesystem remote with
   `git fetch local main`. Inspect the fetched commit and confirm it matches
   the primary checkout's `main`. Merge that local destination history into
   the candidate topic branch if needed, preserving both histories. Use an
   explicit merge message and `GIT_EDITOR=true`; do not rebase or force-update
   either branch. Inspect the complete candidate diff relative to destination
   `main`, not just the last commit.

## Conflicts

Resolve conflicts automatically only when the intended outcome is clear from
both changes and the request. Preserve unrelated work and functionality on
both sides; do not use blanket ours/theirs selection. Inspect the result and
rerun affected checks after any resolution.

If intent is ambiguous, stop, describe the conflicting paths and decision
needed, and report that the changes have not landed. Leave unrelated work
untouched. Do not claim a conflicted or partially merged branch is landed.

## Verification of the exact candidate

Run checks on the final candidate after incorporating the current destination
history and resolving conflicts, before merging into the primary checkout.
All applicable required checks must have passed for those exact changes.
Pending, failing, missing, or unverifiable checks are blockers, not success.
Do not rely on results from an earlier version or silently waive failures.

- For frontend changes, use Node satisfying the locked Vite requirement
  `^20.19.0 || >=22.12.0`. Source: `frontend/pnpm-lock.yaml`, package
  `vite@7.1.7`. At installation the default Node was 14.21.3, but
  `$HOME/.nvm/versions/node/v20.20.2/bin/node` was installed and compatible.
  If that version still exists, prepend its directory to `PATH` for the
  commands below; otherwise locate an installed compatible version or stop
  for setup. Do not silently install or change the user's default runtime.
- In `frontend`, install dependencies using `pnpm install --frozen-lockfile`
  if needed, then run `pnpm check` and `pnpm build`. Sources:
  `frontend/package.json` scripts `check` (`svelte-kit sync && svelte-check
  --tsconfig ./tsconfig.json`) and `build` (`vite build`), and
  `frontend/pnpm-lock.yaml` for the dependency snapshot. The frozen-lockfile
  option is supported by the inspected pnpm 10.18.2 `install` command; stop
  on a lockfile mismatch rather than updating it as a landing side effect.
  The repository's `.npmrc` has `engine-strict=true`.
- For Rust, manifest, build-script, or backend-test changes, run `cargo check`
  and the applicable `cargo test` suite from the repository root. Sources:
  `bacon.toml` jobs `check` and `test` define exactly these invocations;
  `Cargo.toml` declares edition 2024 and the crate/test dependencies.
  Verify the installed Rust toolchain supports the current manifest.
  `build.rs` invokes `pnpm install` and `pnpm run build`, so ensure the same
  compatible Node and pnpm are available to Cargo. Review any tracked
  lockfile changes from that build and do not include unintended updates.
- Before executing backend tests, establish that their database and mail
  configuration is safe and isolated. `src/config.rs::get_config` selects
  `test-config.toml` for `AXUMATIC_ENVIRONMENT=TEST`, but that file currently
  points at hosted Neon PostgreSQL and SES and has `send_emails = true`.
  `tests/axumatic_tests.rs::run_test_app` starts real application state, and
  its test helpers mutate database rows. Merely setting `TEST` does not
  isolate these services. Do not run the suite against real services,
  recreate a database, provision containers, or alter credentials without
  explicit authorization. Stop for an approved isolated configuration if
  it is unavailable; do not substitute compiler success for required tests.
  Never print credential values or commit secrets. Names of environment
  prerequisites are documented in `README.md` and consumed in `src/config.rs`.
- For frontend-only changes, do not require backend integration tests; use
  the frontend checks above and focused behavior verification appropriate
  to the requested change. For documentation/skill-only changes, validate
  changed content and frontmatter without unrelated builds. No repository
  policy currently mandates a full build for these changes.
- Check the candidate diff for whitespace errors with `git diff --check`
  against the recorded destination commit. Inspect generated output and
  working-tree status; do not commit build artifacts or unrelated edits.
- If new repository policy mandates additional checks or reviews, verify
  all applicable requirements for the exact candidate. Do not publish code
  to obtain remote checks without separate authorization; if such a
  requirement cannot be met locally, report the blocker and do not land.

## Merge into local main and confirm

1. Record the tested candidate commit. Recheck the primary checkout's `main`
   commit, branch, and status immediately before merging. If `main` moved,
   incorporate its new history into the candidate and repeat the applicable
   checks. If it has new unrelated work that prevents safe landing, stop.
   Do not switch the primary checkout away from another active branch without
   the user's direction; report that destination state as a blocker.
2. Make the tested source commit available to the authorized primary checkout
   using a fetch from the source workspace's local filesystem repository.
   Confirm the fetched commit ID is the tested candidate. This is a local
   transfer, not publication or a push to `origin` or `local`.
3. In the authorized primary checkout on `main`, perform a normal merge of
   that exact commit: fast-forward when possible, otherwise preserve history
   with a merge commit. Use `GIT_EDITOR=true git merge` with an explicit
   message and `--no-edit`; do not use force, reset, rebase, or squash.
   Ensure local configuration does not force squash or another incompatible
   strategy. If there is an unexpected conflict at this stage, apply the
   conflict policy, then verify the resolved candidate before completing
   the landing; never merge an untested resolution into `main`.
4. Verify that primary `main` contains the tested candidate using
   `git merge-base --is-ancestor`, and confirm its tree matches the tested
   candidate tree. A difference requires investigation and affected checks;
   it is not automatically success. Recheck status and confirm unrelated
   files and changes were preserved. Leave the primary checkout on `main`.
5. Report the primary checkout, destination branch, resulting commit ID,
   checks that passed, and that no remote push occurred. Preparing a commit,
   fetching it, or beginning checks is not landing success. On any blocker,
   state explicitly that the changes have not landed and explain what is
   needed to continue. Keep the topic branch for recovery; do not delete
   branches or clean files as an automatic finishing step.
