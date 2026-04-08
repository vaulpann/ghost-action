# Publishing Ghost To GitHub Marketplace

Use this directory as the full contents of a dedicated public repository, for example `vaulpann/ghost-action`.

## Required Repo Layout

The published repository root should contain:

- `action.yml`
- `README.md`
- `LICENSE`
- `package.json`
- `src/index.js`

Do not publish this action directly from the monorepo. GitHub Marketplace action repositories expect a single root `action.yml` and no workflow files, so this action should live in its own repository when you publish it.

## Recommended Repo Setup

1. Create a new public repo named `ghost-action`.
2. Copy the contents of this directory into the root of that repo.
3. Ensure the repo contains no `.github/workflows/*` files.
4. Push the initial commit.
5. Create a release tag such as `v1.0.0`.
6. Create a moving major tag such as `v1`.
7. Open the root `action.yml` on GitHub and draft a release.
8. Select `Publish this Action to the GitHub Marketplace` and publish the release.

## Versioning

- Use immutable release tags like `v1.0.0`
- Maintain a major tag like `v1`
- Consumers should pin to `@v1`

## Pre-Publish Checklist

- Action repository is public
- `action.yml` is at the repository root
- No workflow files exist in the action repository
- The `name` in `action.yml` is unique in Marketplace
- The README usage example points to the published repo and major tag
- A release tag has been created

GitHub also requires the Marketplace agreement to be accepted before publishing, and publishing a release requires two-factor authentication.
