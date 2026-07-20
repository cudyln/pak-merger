[CmdletBinding()]
param(
    [string]$CargoPath = "cargo",
    [switch]$SkipQualityChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$appRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$targetTriple = "x86_64-pc-windows-msvc"
$binaryName = "pak-merger.exe"
$distRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot "dist"))
$packageRoot = [System.IO.Path]::GetFullPath((Join-Path $distRoot "Pak-Merger-windows-x64"))
$releaseTargetRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot "target\official-release"))
$builtBinary = Join-Path $releaseTargetRoot "$targetTriple\release\$binaryName"
$stagingRoot = [System.IO.Path]::GetFullPath((Join-Path $distRoot ".release-staging-$PID"))
$backupRoot = [System.IO.Path]::GetFullPath((Join-Path $distRoot ".release-previous-$PID"))
$licensesRoot = Join-Path $stagingRoot "licenses"
$profilesRoot = Join-Path $stagingRoot "profiles"
$licenseInventoryPath = Join-Path $licensesRoot "rust-dependencies.json"
$licenseCollector = Join-Path $PSScriptRoot "collect-rust-licenses.ps1"

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $childFull = [System.IO.Path]::GetFullPath($Child)
    $parentFull = [System.IO.Path]::GetFullPath($Parent)
    $prefix = $parentFull.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description is outside the release directory: $childFull"
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    & $script:CargoExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Pak Merger v1 release builds are supported only on Windows."
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Pak Merger v1 requires a 64-bit Windows build host."
}

$cargo = Get-Command -Name $CargoPath -ErrorAction Stop
$script:CargoExecutable = $cargo.Source
$rustcPath = Join-Path (Split-Path -Parent $cargo.Source) "rustc.exe"
if (-not (Test-Path -LiteralPath $rustcPath -PathType Leaf)) {
    throw "rustc.exe was not found beside Cargo: $rustcPath"
}

$overrideEnvironment = @(
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS",
    "CARGO_PROFILE_RELEASE_OPT_LEVEL",
    "CARGO_PROFILE_RELEASE_LTO",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
    "CARGO_PROFILE_RELEASE_DEBUG",
    "CARGO_PROFILE_RELEASE_INCREMENTAL",
    "CARGO_PROFILE_RELEASE_PANIC",
    "CARGO_PROFILE_RELEASE_STRIP"
)
foreach ($name in $overrideEnvironment) {
    $value = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not [string]::IsNullOrWhiteSpace($value)) {
        throw "Release profile override environment variable is not allowed: $name"
    }
}

Push-Location -LiteralPath $appRoot
try {
    $metadataText = (& $cargo.Source metadata --locked --offline --no-deps --format-version 1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

$metadata = $metadataText | ConvertFrom-Json
$manifestPath = [System.IO.Path]::GetFullPath((Join-Path $appRoot "Cargo.toml"))
$rootPackages = @($metadata.packages | Where-Object {
    [System.IO.Path]::GetFullPath([string]$_.manifest_path) -eq $manifestPath
})
if ($rootPackages.Count -ne 1) {
    throw "Cargo metadata did not identify exactly one application package."
}
$productVersion = [string]$rootPackages[0].version
$productMetadata = $rootPackages[0].metadata.'pak-merger'
$expectedRepakRevision = [string]$productMetadata.repak_upstream_revision
$repakVendorPatch = [string]$productMetadata.repak_vendor_patch
if ($expectedRepakRevision -notmatch '^[0-9a-f]{40}$') {
    throw "Cargo metadata does not contain a valid pinned repak upstream revision."
}
if ([string]::IsNullOrWhiteSpace($repakVendorPatch)) {
    throw "Cargo metadata does not name the vendored repak patch."
}
$repakVendorRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot "vendor\repak"))
$repakRevisionPath = Join-Path $repakVendorRoot "UPSTREAM_REVISION"
$repakPatchesPath = Join-Path $repakVendorRoot "PATCHES.md"
foreach ($requiredVendorFile in @($repakRevisionPath, $repakPatchesPath)) {
    if (-not (Test-Path -LiteralPath $requiredVendorFile -PathType Leaf)) {
        throw "Vendored repak provenance file is missing: $requiredVendorFile"
    }
}
$repakRevision = (Get-Content -LiteralPath $repakRevisionPath -Raw -Encoding UTF8).Trim().ToLowerInvariant()
if ($repakRevision -ne $expectedRepakRevision) {
    throw "Vendored repak revision mismatch: Cargo metadata requires $expectedRepakRevision, provenance file declares $repakRevision."
}
$cargoVersion = ((& $cargo.Source --version --verbose) | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "cargo version query failed."
}
$rustcVersion = ((& $rustcPath -vV) | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "rustc version query failed."
}
$cargoLockPath = Join-Path $appRoot "Cargo.lock"
$cargoLockHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $cargoLockPath).Hash.ToLowerInvariant()

Push-Location -LiteralPath $appRoot
try {
    if (-not $SkipQualityChecks) {
        Invoke-Cargo -Description "cargo fmt" -Arguments @("fmt", "--all", "--", "--check")
        Invoke-Cargo -Description "vendored repak fmt" -Arguments @(
            "fmt", "--manifest-path", "vendor/repak/Cargo.toml", "--all", "--", "--check"
        )
        Invoke-Cargo -Description "cargo test" -Arguments @(
            "test", "--frozen", "--target", $targetTriple, "--all-targets"
        )
        Invoke-Cargo -Description "vendored repak tests" -Arguments @(
            "test",
            "--manifest-path", "vendor/repak/Cargo.toml",
            "--frozen",
            "--target", $targetTriple,
            "--target-dir", $releaseTargetRoot,
            "-p", "repak",
            "--lib",
            "--no-default-features",
            "--features", "compression,oodle"
        )
        Invoke-Cargo -Description "cargo clippy" -Arguments @(
            "clippy", "--frozen", "--target", $targetTriple, "--all-targets", "--", "-D", "warnings"
        )
        Invoke-Cargo -Description "vendored repak clippy" -Arguments @(
            "clippy",
            "--manifest-path", "vendor/repak/Cargo.toml",
            "--frozen",
            "--target", $targetTriple,
            "--target-dir", $releaseTargetRoot,
            "-p", "repak",
            "--lib",
            "--no-default-features",
            "--features", "compression,oodle",
            "--", "-D", "warnings"
        )
    }
    Invoke-Cargo -Description "cargo release build" -Arguments @(
        "build",
        "--release",
        "--frozen",
        "--target", $targetTriple,
        "--target-dir", $releaseTargetRoot,
        "--bin", "pak-merger"
    )
}
finally {
    Pop-Location
}

if (-not (Test-Path -LiteralPath $builtBinary -PathType Leaf)) {
    throw "Expected release executable was not created: $builtBinary"
}
$expectedVersionText = "pak-merger $productVersion"
$actualVersionText = ((& $builtBinary --version) | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $actualVersionText -ne $expectedVersionText) {
    throw "Executable version mismatch: expected '$expectedVersionText', got '$actualVersionText'."
}

$binaryAscii = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($builtBinary))
foreach ($dynamicRuntime in @("VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "MSVCP140.dll")) {
    if ($binaryAscii.IndexOf($dynamicRuntime, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "The release executable still imports the dynamic MSVC runtime: $dynamicRuntime"
    }
}

New-Item -ItemType Directory -Force -Path $distRoot | Out-Null
foreach ($path in @($packageRoot, $stagingRoot, $backupRoot)) {
    Assert-ChildPath -Child $path -Parent $distRoot -Description "Release path"
}
if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}
if (Test-Path -LiteralPath $backupRoot) {
    Remove-Item -LiteralPath $backupRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $licensesRoot | Out-Null
New-Item -ItemType Directory -Force -Path $profilesRoot | Out-Null

$promoted = $false
try {
    $packageFiles = @(
        @{ Source = $builtBinary; Destination = (Join-Path $stagingRoot $binaryName) },
        @{ Source = (Join-Path $appRoot "LICENSE"); Destination = (Join-Path $stagingRoot "LICENSE") },
        @{ Source = (Join-Path $appRoot "README.md"); Destination = (Join-Path $stagingRoot "README.md") },
        @{ Source = (Join-Path $appRoot "README.ko.md"); Destination = (Join-Path $stagingRoot "README.ko.md") },
        @{ Source = (Join-Path $appRoot "THIRD_PARTY_NOTICES.md"); Destination = (Join-Path $stagingRoot "THIRD_PARTY_NOTICES.md") },
        @{ Source = (Join-Path $appRoot "assets\EULA.ko.md"); Destination = (Join-Path $stagingRoot "EULA.ko.md") },
        @{ Source = (Join-Path $appRoot "assets\EULA.en.md"); Destination = (Join-Path $stagingRoot "EULA.en.md") },
        @{ Source = (Join-Path $appRoot "assets\EULA.ja.md"); Destination = (Join-Path $stagingRoot "EULA.ja.md") },
        @{ Source = (Join-Path $appRoot "profiles\README.md"); Destination = (Join-Path $profilesRoot "README.md") },
        @{ Source = (Join-Path $appRoot "profiles\README.ko.md"); Destination = (Join-Path $profilesRoot "README.ko.md") },
        @{ Source = (Join-Path $appRoot "profiles\example-game.profile.json"); Destination = (Join-Path $profilesRoot "example-game.profile.json") },
        @{ Source = (Join-Path $appRoot "licenses\repak-LICENSE-MIT.txt"); Destination = (Join-Path $licensesRoot "repak-LICENSE-MIT.txt") },
        @{ Source = (Join-Path $appRoot "licenses\repak-LICENSE-APACHE-2.0.txt"); Destination = (Join-Path $licensesRoot "repak-LICENSE-APACHE-2.0.txt") },
        @{ Source = $repakPatchesPath; Destination = (Join-Path $licensesRoot "repak-PATCHES.md") },
        @{ Source = (Join-Path $appRoot "licenses\tabler-icons-MIT.txt"); Destination = (Join-Path $licensesRoot "tabler-icons-MIT.txt") }
    )
    foreach ($item in $packageFiles) {
        if (-not (Test-Path -LiteralPath $item.Source -PathType Leaf)) {
            throw "Required package input is missing: $($item.Source)"
        }
        Copy-Item -LiteralPath $item.Source -Destination $item.Destination -Force
    }

    if (-not (Test-Path -LiteralPath $licenseCollector -PathType Leaf)) {
        throw "Rust license collector is missing: $licenseCollector"
    }
    & $licenseCollector -CargoPath $cargo.Source -Destination $licensesRoot -TargetTriple $targetTriple
    if (-not (Test-Path -LiteralPath $licenseInventoryPath -PathType Leaf)) {
        throw "Rust dependency license inventory was not created: $licenseInventoryPath"
    }
    $licenseInventory = Get-Content -LiteralPath $licenseInventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($licenseInventory.allCargoLicenseExpressionsPresent -ne $true) {
        throw "The dependency inventory did not validate every Cargo license expression."
    }
    if (@($licenseInventory.packagesWithoutCopiedLicenseFiles).Count -ne 0) {
        throw "The dependency inventory contains packages without copied license files."
    }
    if ([string]$licenseInventory.cargoLockSha256 -ne $cargoLockHash) {
        throw "The dependency inventory was generated from a different Cargo.lock."
    }

    $repakPackages = @($licenseInventory.packages | Where-Object { $_.name -eq "repak" })
    if ($repakPackages.Count -ne 1) {
        throw "The release dependency inventory must contain exactly one repak package."
    }
    $repakSource = [string]$repakPackages[0].source
    if ($repakSource -ne "vendored:vendor/repak/repak/Cargo.toml") {
        throw "The release must use the audited vendored repak source, got: $repakSource"
    }

    $forbiddenExtensions = @(".pak", ".utoc", ".ucas", ".sig", ".key")
    $forbiddenNamePatterns = @("unrealpak", "oo2core")
    $packageEntries = @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -File)
    foreach ($entry in $packageEntries) {
        if ($forbiddenExtensions -contains $entry.Extension.ToLowerInvariant()) {
            throw "Forbidden game/mod container or key-like file in release package: $($entry.FullName)"
        }
        $lowerName = $entry.Name.ToLowerInvariant()
        foreach ($pattern in $forbiddenNamePatterns) {
            if ($lowerName.Contains($pattern)) {
                throw "Forbidden external-tool or codec-like file in release package: $($entry.FullName)"
            }
        }
        if ($entry.Extension -ieq ".dll") {
            throw "Release package must not contain runtime DLLs: $($entry.FullName)"
        }
    }

    $binaryHash = Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stagingRoot $binaryName)
    $stagingPrefix = $stagingRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $fileInventory = @(Get-ChildItem -LiteralPath $stagingRoot -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            if (-not $_.FullName.StartsWith($stagingPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Packaged file is outside the staging directory: $($_.FullName)"
            }
            $relativePath = $_.FullName.Substring($stagingPrefix.Length).Replace('\', '/')
            [ordered]@{
                path = $relativePath
                size = $_.Length
                sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            }
        })
    $manifest = [ordered]@{
        schemaVersion = 1
        product = "Pak Merger"
        version = $productVersion
        releaseChannel = "stable"
        binary = $binaryName
        target = $targetTriple
        sha256 = $binaryHash.Hash.ToLowerInvariant()
        build = [ordered]@{
            cargoLockSha256 = $cargoLockHash
            cargoVersion = $cargoVersion
            rustcVersion = $rustcVersion
            qualityChecksPerformed = -not [bool]$SkipQualityChecks
        }
        repak = [ordered]@{
            revision = $repakRevision
            source = $repakSource
            changes = $repakVendorPatch
        }
        dependencyLicenses = "licenses/rust-dependencies.json"
        files = $fileInventory
    }

    $manifestPath = Join-Path $stagingRoot "build-manifest.json"
    $manifestJson = $manifest | ConvertTo-Json -Depth 8
    $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, $utf8NoBom)

    $hadPreviousPackage = Test-Path -LiteralPath $packageRoot
    if ($hadPreviousPackage) {
        Move-Item -LiteralPath $packageRoot -Destination $backupRoot
    }
    try {
        Move-Item -LiteralPath $stagingRoot -Destination $packageRoot
        $promoted = $true
    }
    catch {
        if ($hadPreviousPackage -and (Test-Path -LiteralPath $backupRoot) -and -not (Test-Path -LiteralPath $packageRoot)) {
            Move-Item -LiteralPath $backupRoot -Destination $packageRoot
        }
        throw
    }
    if (Test-Path -LiteralPath $backupRoot) {
        Remove-Item -LiteralPath $backupRoot -Recurse -Force
    }

    Write-Host "Pak Merger release package created: $packageRoot"
    Write-Host "pak-merger.exe SHA-256: $($binaryHash.Hash.ToLowerInvariant())"
}
finally {
    if (-not $promoted -and (Test-Path -LiteralPath $stagingRoot)) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}
