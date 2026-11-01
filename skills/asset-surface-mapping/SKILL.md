---
name: asset-surface-mapping
description: Map discovered assets without silently expanding scope.
version: 0.2.0
metadata:
  hermes:
    tags: [security, assets, mapping]
    category: security
---
# Asset and Surface Mapping

## When to Use
Use when building an inventory from user-supplied assets or previously authorized observations.

## Procedure
1. Preserve each asset's original locator and discovery provenance.
2. Classify each asset against the active authorization envelope.
3. Use `vane_plan_web2` to produce passive work items for explicitly in-scope Web2 assets.
4. Keep out-of-scope assets in the inventory as OUT_OF_SCOPE or NOT_INSPECTED.
5. Record redirects, aliases, dependencies, and symlink targets as relationships, not scope grants.
6. Build a dependency graph only from evidence-backed relationships. Traverse only nodes explicitly marked in scope.

## Pitfalls
- Do not probe a discovered asset to determine whether it is in scope.
- Do not silently drop unresolved or inaccessible assets.
- DNS resolution, certificate names, page links, and redirects do not grant authority.

## Verification
Report the asset count by disposition, provenance for each discovered asset, and all unresolved scope questions.
