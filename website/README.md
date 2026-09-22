# Ghostunnel Website

This directory contains the [Hugo](https://gohugo.io/) source for the
Ghostunnel project website.

## Prerequisites

Install Hugo (extended edition):

```bash
# macOS
brew install hugo

# Linux (snap)
snap install hugo

# From source
go install github.com/gohugoio/hugo@latest
```

## Local Development

From the repository root:

```bash
go tool mage website:serve
```

This generates the contributors page from Git history, then starts a local
Hugo server at http://localhost:1313/ with live reload.

## Building

```bash
go tool mage website:build
```

This generates the contributors page and builds the site into `website/public/`.

## Available Mage Targets

```bash
go tool mage website:contrib   # Generate contributors page from git history
go tool mage website:build     # Generate contributors + build Hugo site
go tool mage website:serve     # Generate contributors + start dev server
```

## Content

The site pulls content from existing repository files via Hugo module mounts:

- **Homepage**: `website/content/_index.md`
- **Documentation**: `docs/` directory (mounted into the site automatically)
- **Releases**: `releases/` directory (mounted into the site automatically)
- **Contributors**: Generated at build time from Git history (not checked in)

To add or edit documentation, modify the files in `docs/` directly. To add a
new release, add a Markdown file to `releases/` with the appropriate YAML
frontmatter (see existing files for the format).

## Unreleased Documentation

Documentation for a feature that has not shipped yet is kept off the published
site until the release that ships it, so that master can carry the docs
alongside the code without the website describing features nobody can use.

Pages declare the release they belong to with a `since` field in their front
matter:

```yaml
---
title: Software Bill of Materials
since: v1.12.0
---
```

For a paragraph on a page that is otherwise released, use the `since`
shortcode instead. Note the `{{%` delimiters, which keep the enclosed Markdown
part of the surrounding page:

```markdown
{{% since "v1.12.0" %}}
Every published image carries an SBOM attestation.
{{% /since %}}
```

Both are compared against the newest non-prerelease version in `releases/`, so
nothing has to be flipped by hand: adding `releases/v1.12.0.md` for the release
makes the pages and paragraphs gated on `v1.12.0` appear on the next build. A
hidden page is dropped from the build entirely, which keeps it out of the
sidebar, the section listings and the search index as well.

Anything that links to a hidden page has to be gated too, otherwise the link
check in the website workflow fails on the dangling link.

To review unreleased documentation locally, build with the pages included:

```bash
GHOSTUNNEL_DOCS_PREVIEW=1 go tool mage website:serve
```

`website:build` prints the pages it hides on every run, and generates
`website/hugo.generated.toml` (not checked in) to pass the release information
to Hugo. Build the site through mage rather than calling `hugo` directly, or
that file will be stale or missing.

## Deployment

The site is automatically deployed to GitHub Pages via the
`.github/workflows/website.yml` workflow on push to `master`. The workflow
triggers when changes are made to `website/`, `docs/`, or `releases/`.
The contributors page is generated fresh during each build.
