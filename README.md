# Pak Merger

English | [한국어](README.ko.md)

Pak Merger combines compatible mod Pak files into one file. Changes that do not overlap are merged automatically. If two mods change the same item differently, you choose which Pak to use.

The Windows GUI and CLI are included in a single `pak-merger.exe`. UnrealPak is not required.

## What It Can Merge

- Files that exist in only one input Pak are added automatically.
- Input Paks can modify different parts of the game's `Content` folder.
- For supported databases, Pak Merger combines field-level changes instead of replacing the whole file.
- If two Paks change the same field differently, you choose which value to keep.
- If a file cannot be compared safely, you choose one Pak for the complete related file group.

Field-level database merging is currently tuned for OCTOPATH TRAVELER 0. Other readable Unreal Paks can still be combined, but unfamiliar game data may require a whole-file choice.

## Supported Files

- Windows x64
- Up to 64 Pak files and 128 GiB total per job
- Unencrypted Pak versions 0 through 11 as input
- Uncompressed, Zlib, Gzip, Zstd, LZ4, and Oodle-compressed input
- Unencrypted, unsigned Pak version 11 output
- Uncompressed or Oodle-compressed output
- Korean, English, and Japanese interface and Terms of Use

Encrypted Pak files, IoStore files (`.utoc`/`.ucas`), damaged files, and unsupported compression formats cannot be opened. Pak Merger does not accept AES keys.

Oodle support uses `oo2core_9_win64.dll`. If it is missing, Pak Merger downloads and verifies it the first time Oodle is needed. This requires an internet connection and permission to write beside the executable.

## Using the GUI

1. Run `pak-merger.exe` and accept the Terms of Use.
2. Add at least two Pak files. Drag and drop is supported.
3. Choose the **Base Pak**. This keeps the default format for content that does not require a choice; it does not automatically win conflicts.
4. Select **Analyze**.
5. Choose which Pak to use for every unresolved item.
6. Select **Build merged Pak**.

The default filename is `ZZMerge_P.pak`. The `ZZ` prefix helps place the merged Pak late in the usual filename-based load order. You may rename it, but keep the `_P.pak` suffix.

If the destination file already exists, Pak Merger asks before replacing it. Input Pak files are opened read-only and are never moved, deleted, or installed automatically.

After the merge, load only the new merged Pak. Leaving the original mod Pak files enabled may overwrite part of the merged result.

## Temporary Files and Free Space

Temporary work is stored in the `tmp` folder beside `pak-merger.exe`. You can save the merged Pak to another drive, but both drives need enough free space for the job.

## Options and Progress

The default output uses **Oodle compression** and **multithreading**.

- Choose **No compression** for a larger file without compression work.
- Turn off **Multithreading** only when troubleshooting.
- Output options are locked while analysis or Pak creation is running.

The current stage and progress are shown in the window. **Cancel operation** stops the job as soon as it can and removes temporary files created by Pak Merger.

## CLI

Use the built-in help for all commands and options:

```powershell
.\pak-merger.exe --help
.\pak-merger.exe <command> --help
```

Basic workflow:

```powershell
.\pak-merger.exe inspect '.\ModA_P.pak'

.\pak-merger.exe analyze `
  --pak '.\ModA_P.pak' `
  --pak '.\ModB_P.pak' `
  --base-pak '.\ModA_P.pak' `
  --output '.\merge-plan.json'

.\pak-merger.exe merge `
  --plan '.\merge-plan.json' `
  --choose 'conflict-id=pak-option-id' `
  --output '.\ZZMerge_P.pak'

.\pak-merger.exe verify '.\ZZMerge_P.pak'
```

`merge` does not replace an existing output unless `--overwrite` is supplied. Add `--compression none` for uncompressed output; Oodle is the default.

### Terms of Use

```powershell
.\pak-merger.exe eula
.\pak-merger.exe eula --true
```

`eula` displays the bundled terms. After reading them, use `eula --true` to record acceptance. You may add `--locale ko`, `--locale en`, or `--locale ja`; English is used by default.

Use `.\pak-merger.exe eula --help` for status and withdrawal commands.

## License

Pak Merger's own code is available for personal, non-commercial use under the [Pak Merger Non-Commercial Source License](LICENSE). Third-party components keep their own licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
