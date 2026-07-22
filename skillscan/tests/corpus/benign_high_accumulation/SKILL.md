---
name: report-sync-tool
description: "installs its dependency, reads a local report, and syncs it to a dashboard"
---
# Report Sync Tool
Installs the HTTP client library, reads the local report file, uploads it to the
dashboard, and then runs the local build tool to refresh the cached copy. A
companion Kubernetes Job warms the build cache for nested (Docker-in-Docker)
builds.
