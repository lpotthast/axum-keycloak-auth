# AGENTS.md

## Required Change Workflow

Use `## [Unreleased]` in `CHANGELOG.md` as the default landing place for change entries while work is in progress.  
Use the last "## [version] - date" section if this version was not yet released. It is the next planned upcoming release  
and all changes must be appended to that section instead of falsely being added to "## [Unreleased]".

1. Record the net release-notable effect of each change under the appropriate section in `## [Unreleased]`.  
   Before adding a new item, inspect existing `Unreleased` entries for the same feature, fix, or design area.  
   Update, merge, or remove related entries so the changelog describes the final current behavior, not intermediary  
   iterations.
2. Re-evaluate the SemVer impact of the resulting changelog entry when you add or revise it.
3. If a change is SemVer-breaking, start its Markdown list item with `- **Breaking:** ...`.
4. Do not bump crate versions or README dependency snippets for ordinary in-progress changes.

Right before publishing:

1. Inspect the `## [Unreleased]` section and determine the next version from the accumulated changes.
2. Treat any `- **Breaking:** ...` entry as the indicator that the release requires a breaking version bump.
3. Move the accumulated unreleased entries into a new `## [x.y.z] - YYYY-MM-DD` section.
4. Bump the affected crate version(s) accordingly.
5. Update every README installation example to reference the new crate version.
6. Extend the comparison link list at the end of `CHANGELOG.md` for the new version and update `[Unreleased]` to compare  
   from the new tag.
7. Run `just tidy` as the final verification step.
