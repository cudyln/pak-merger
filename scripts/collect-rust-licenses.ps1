[CmdletBinding()]
param(
    [string]$CargoPath = "cargo",
    [Parameter(Mandatory = $true)]
    [string]$Destination,
    [string]$TargetTriple = "x86_64-pc-windows-msvc"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$appRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$cargo = Get-Command -Name $CargoPath -ErrorAction Stop
$destinationRoot = [System.IO.Path]::GetFullPath($Destination)
$rustLicenseRoot = Join-Path $destinationRoot "rust"
$inventoryPath = Join-Path $destinationRoot "rust-dependencies.json"
$apacheFallbackPath = Join-Path $appRoot "licenses\repak-LICENSE-APACHE-2.0.txt"
$bslFallbackPath = Join-Path $appRoot "licenses\spdx\BSL-1.0.txt"

$fallbackSources = @{
    "Apache-2.0" = [ordered]@{
        path = $apacheFallbackPath
        sha256 = "62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a"
    }
    "BSL-1.0" = [ordered]@{
        path = $bslFallbackPath
        sha256 = "c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566"
    }
}
$fallbackLicenses = @{
    "clipboard-win|5.4.1|BSL-1.0" = "BSL-1.0"
    "ecolor|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "eframe|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "egui|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "egui_glow|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "egui-winit|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "emath|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "epaint|0.32.3|MIT OR Apache-2.0" = "Apache-2.0"
    "gl_generator|0.14.0|Apache-2.0" = "Apache-2.0"
    "khronos_api|3.1.0|Apache-2.0" = "Apache-2.0"
    "profiling|1.0.18|MIT OR Apache-2.0" = "Apache-2.0"
}
foreach ($fallback in $fallbackSources.GetEnumerator()) {
    $fallbackPath = [string]$fallback.Value.path
    if (-not (Test-Path -LiteralPath $fallbackPath -PathType Leaf)) {
        throw "Checked-in fallback license file is missing: $fallbackPath"
    }
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $fallbackPath).Hash.ToLowerInvariant()
    if ($actualHash -ne [string]$fallback.Value.sha256) {
        throw "Fallback license hash mismatch for $($fallback.Key): $actualHash"
    }
}

if (Test-Path -LiteralPath $rustLicenseRoot) {
    Remove-Item -LiteralPath $rustLicenseRoot -Recurse -Force
}
if (Test-Path -LiteralPath $inventoryPath -PathType Leaf) {
    Remove-Item -LiteralPath $inventoryPath -Force
}
New-Item -ItemType Directory -Force -Path $rustLicenseRoot | Out-Null

Push-Location -LiteralPath $appRoot
try {
    $metadataText = (& $cargo.Source metadata --locked --offline --filter-platform $TargetTriple --format-version 1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

$metadata = $metadataText | ConvertFrom-Json
if ($null -eq $metadata.resolve -or [string]::IsNullOrWhiteSpace($metadata.resolve.root)) {
    throw "Cargo metadata did not contain a resolved root package."
}

$nodesById = @{}
foreach ($node in $metadata.resolve.nodes) {
    $nodesById[$node.id] = $node
}

$reachable = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$pending = [System.Collections.Generic.Queue[string]]::new()
$pending.Enqueue([string]$metadata.resolve.root)
while ($pending.Count -gt 0) {
    $packageId = $pending.Dequeue()
    if (-not $reachable.Add($packageId)) {
        continue
    }
    if (-not $nodesById.ContainsKey($packageId)) {
        throw "Resolved dependency node is missing from Cargo metadata: $packageId"
    }
    foreach ($dependency in $nodesById[$packageId].deps) {
        $isReleaseDependency = $false
        foreach ($kind in $dependency.dep_kinds) {
            if ($null -eq $kind.kind -or $kind.kind -eq "normal" -or $kind.kind -eq "build") {
                $isReleaseDependency = $true
            }
        }
        if ($isReleaseDependency) {
            $pending.Enqueue([string]$dependency.pkg)
        }
    }
}

$rootId = [string]$metadata.resolve.root
$packages = @($metadata.packages |
    Where-Object { $_.id -ne $rootId -and $reachable.Contains([string]$_.id) } |
    Sort-Object name, version, id)
if ($packages.Count -eq 0) {
    throw "No third-party release dependencies were resolved."
}

$inventoryPackages = @()
$missingLicenseFiles = @()
$fallbackLicensePackageCount = 0
$seenPackageDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($package in $packages) {
    if ([string]::IsNullOrWhiteSpace([string]$package.license)) {
        throw "Third-party package has no Cargo license expression: $($package.name) $($package.version)"
    }

    $safeName = ([string]$package.name -replace '[^A-Za-z0-9._-]', '_')
    $safeVersion = ([string]$package.version -replace '[^A-Za-z0-9._+-]', '_')
    $packageDirectoryName = "$safeName-$safeVersion"
    if (-not $seenPackageDirectories.Add($packageDirectoryName)) {
        throw "Two resolved packages map to the same license directory: $packageDirectoryName"
    }

    $manifestPath = [System.IO.Path]::GetFullPath([string]$package.manifest_path)
    $sourceDirectory = Split-Path -Parent $manifestPath
    if (-not (Test-Path -LiteralPath $sourceDirectory -PathType Container)) {
        throw "Resolved package source directory is unavailable: $sourceDirectory"
    }

    $licenseCandidates = @(Get-ChildItem -LiteralPath $sourceDirectory -Recurse -File |
        Where-Object {
            $_.Name -match '(?i)^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|UNLICENSE|OFL|UFL)([._-].*)?$' -or
            ($package.name -eq "epaint_default_fonts" -and
                $_.Directory.Name -eq "fonts" -and
                $_.Extension -eq ".txt")
        } |
        Sort-Object FullName)

    # Vendored workspace licenses may sit above the member crate.
    $vendorRoot = [System.IO.Path]::GetFullPath((Join-Path $appRoot "vendor"))
    $vendorPrefix = $vendorRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $sourceIsVendored = $sourceDirectory.StartsWith(
        $vendorPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    if ($licenseCandidates.Count -eq 0 -and
        ([string]$package.source -like "git+*" -or $sourceIsVendored)) {
        $ancestor = [System.IO.DirectoryInfo]::new($sourceDirectory)
        for ($depth = 0; $depth -lt 4; $depth++) {
            $ancestor = $ancestor.Parent
            if ($null -eq $ancestor -or $ancestor.Name -in @("checkouts", "git", ".cargo")) {
                break
            }
            $licenseCandidates = @(Get-ChildItem -LiteralPath $ancestor.FullName -File |
                Where-Object {
                    $_.Name -match '(?i)^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|UNLICENSE|OFL|UFL)([._-].*)?$'
                } |
                Sort-Object FullName)
            if ($licenseCandidates.Count -gt 0) {
                break
            }
        }
    }

    $selectedLicense = $null
    $fallbackUsed = $false
    if ($licenseCandidates.Count -eq 0) {
        $fallbackKey = "$($package.name)|$($package.version)|$($package.license)"
        if ($fallbackLicenses.ContainsKey($fallbackKey)) {
            if ([string]$package.source -ne "registry+https://github.com/rust-lang/crates.io-index") {
                throw "Fallback license is allowed only for the pinned crates.io package: $fallbackKey"
            }
            $selectedLicense = [string]$fallbackLicenses[$fallbackKey]
            $licenseCandidates = @(Get-Item -LiteralPath ([string]$fallbackSources[$selectedLicense].path))
            $fallbackUsed = $true
            $fallbackLicensePackageCount++
        }
    }

    $copiedFiles = @()
    if ($licenseCandidates.Count -gt 0) {
        $packageLicenseRoot = Join-Path $rustLicenseRoot $packageDirectoryName
        New-Item -ItemType Directory -Force -Path $packageLicenseRoot | Out-Null
        $usedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($candidate in $licenseCandidates) {
            $candidateName = if ($fallbackUsed) {
                "LICENSE-$selectedLicense.txt"
            }
            else {
                $candidate.Name
            }
            if (-not $usedNames.Add($candidateName)) {
                $candidateName = "$(($candidate.Directory.Name -replace '[^A-Za-z0-9._-]', '_'))__$candidateName"
                if (-not $usedNames.Add($candidateName)) {
                    throw "Duplicate license candidate name for $($package.name): $candidateName"
                }
            }
            $destinationFile = Join-Path $packageLicenseRoot $candidateName
            Copy-Item -LiteralPath $candidate.FullName -Destination $destinationFile -Force
            $copiedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destinationFile).Hash.ToLowerInvariant()
            $copiedFiles += [ordered]@{
                path = "rust/$packageDirectoryName/$candidateName"
                sha256 = $copiedHash
                origin = if ($fallbackUsed) { "checked-in-spdx-fallback" } else { "package-source" }
            }
        }
    }
    else {
        $missingLicenseFiles += "$($package.name) $($package.version)"
    }

    $sourceIdentifier = if ($null -ne $package.source) {
        [string]$package.source
    }
    elseif ($sourceIsVendored) {
        $appPrefix = $appRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        $relativeManifest = $manifestPath.Substring($appPrefix.Length).Replace('\', '/')
        "vendored:$relativeManifest"
    }
    else {
        $null
    }

    $inventoryPackages += [ordered]@{
        name = [string]$package.name
        version = [string]$package.version
        source = $sourceIdentifier
        license = [string]$package.license
        selectedLicense = $selectedLicense
        fallbackLicenseUsed = $fallbackUsed
        authors = @($package.authors)
        repository = if ($null -eq $package.repository) { $null } else { [string]$package.repository }
        copiedLicenseFiles = $copiedFiles
    }
}

$lockPath = Join-Path $appRoot "Cargo.lock"
$lockHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $lockPath).Hash.ToLowerInvariant()
$inventory = [ordered]@{
    schemaVersion = 3
    product = "Pak Merger"
    target = $TargetTriple
    cargoLockSha256 = $lockHash
    dependencyScope = "locked Windows x64 normal and build dependencies"
    thirdPartyPackageCount = $inventoryPackages.Count
    allCargoLicenseExpressionsPresent = $true
    fallbackLicensePackageCount = $fallbackLicensePackageCount
    packagesWithCopiedLicenseFiles = $inventoryPackages.Count - $missingLicenseFiles.Count
    packagesWithoutCopiedLicenseFiles = $missingLicenseFiles
    licenseFileDiscovery = "package source, nearest vendored workspace ancestor, or allowlisted SPDX fallback"
    notice = "Missing license files block the release."
    packages = $inventoryPackages
}

$inventoryJson = $inventory | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
[System.IO.File]::WriteAllText($inventoryPath, $inventoryJson, $utf8NoBom)

Write-Host "Rust release dependency inventory: $inventoryPath"
Write-Host "Third-party packages: $($inventoryPackages.Count)"
Write-Host "Packages without copied license files: $($missingLicenseFiles.Count)"
