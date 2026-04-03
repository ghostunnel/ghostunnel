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
go tool mage website:build           # Generate contributors + build Hugo site
go tool mage website:serve           # Generate contributors + start dev server
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

## Deployment

The site is automatically deployed to GitHub Pages via the
`.github/workflows/website.yml` workflow on push to `master`. The workflow
triggers when changes are made to `website/`, `docs/`, or `releases/`.
The contributors page is generated fresh during each build.
