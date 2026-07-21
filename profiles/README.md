# Game Profiles

English | [한국어](README.ko.md)

Game profiles tell Pak Merger which database fields must be selected together. They do not add a new file decoder; the database must already use a format supported by Pak Merger.

Built-in profiles are selected automatically when there is one clear match. If no profile matches, or more than one profile matches equally, Pak Merger uses its general comparison rules.

External JSON profiles can currently be loaded through the Rust library API. A profile picker is not yet available in the GUI or CLI.

## Supported Format

Schema version 1 supports `messagepack_m_data_list_v1`: a MessagePack database with rows stored in `m_DataList` and identified by `m_id`.

A profile contains:

- `schemaVersion`: Must be `1`.
- `id`: Unique profile identifier.
- `displayName`: Name shown to users.
- `format`: Currently `messagepack_m_data_list_v1`.
- `detection`: Pak path rules used to identify the game or data layout.
- `assets`: Rules for matching database files and grouping related fields.

`detection.rootScopeMatchers` limits a selected profile to its own rooted
content paths. Relative paths produced after a common content root is removed
continue to work normally.

Path matchers use `exact`, `prefix`, `suffix`, or `contains`. Paths begin with `/`, use `/` as the separator, and are matched without regard to letter case.

Each asset rule may contain `fieldGroups` with one of these modes:

- `whole_fields`: Select all listed fields from the same Pak.
- `parallel_array_items`: Select matching positions across related arrays when their lengths agree.

Values not listed in a group follow Pak Merger's general rules. Simple top-level values may be selected separately, while arrays and nested values stay together.

## Rust Library API

Load external profiles into a registry, then use the registry-backed analysis
session for both comparison and output. Keep that session alive until writing
finishes; the plan-only `write` function uses built-in profiles only.

```rust
use pak_merger::profiles::{ProfileRegistry, load_external_profile_file};
use pak_merger::{
    AnalysisRequest, ResolutionSet, WriteOptions, analyze_session_with_registry,
    write_session_with_options_and_progress,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

fn merge_with_profile(
    profile_path: &Path,
    first_pak: &Path,
    second_pak: &Path,
    output_pak: &Path,
    choices: BTreeMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ProfileRegistry::with_builtins();
    registry.register(load_external_profile_file(profile_path)?)?;
    let session = analyze_session_with_registry(
        AnalysisRequest {
            pak_paths: vec![first_pak.to_owned(), second_pak.to_owned()],
            carrier_path: first_pak.to_owned(),
        },
        Arc::new(registry),
    )?;

    // Each entry maps a blocking conflict ID from session.plan() to one of
    // that conflict's variant IDs.
    let resolutions = ResolutionSet {
        plan_id: session.plan().plan_id.clone(),
        choices,
    };
    write_session_with_options_and_progress(
        &session,
        resolutions,
        output_pak,
        WriteOptions::default(),
        |_| {},
    )?;
    Ok(())
}
```

## Example

See [`example-game.profile.json`](example-game.profile.json) for a complete fictional profile.
