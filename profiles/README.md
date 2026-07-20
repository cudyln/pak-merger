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

Path matchers use `exact`, `prefix`, `suffix`, or `contains`. Paths begin with `/`, use `/` as the separator, and are matched without regard to letter case.

Each asset rule may contain `fieldGroups` with one of these modes:

- `whole_fields`: Select all listed fields from the same Pak.
- `parallel_array_items`: Select matching positions across related arrays when their lengths agree.

Values not listed in a group follow Pak Merger's general rules. Simple top-level values may be selected separately, while arrays and nested values stay together.

## Example

See [`example-game.profile.json`](example-game.profile.json) for a complete fictional profile.
