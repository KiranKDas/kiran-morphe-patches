#!/usr/bin/env python3
import glob
import json
import os
import re
import sys
import zipfile
from pathlib import Path

def inspect_apk(apk_path: Path):
    print("=" * 60)
    print(f"Inspecting target APK: {apk_path.name}")
    print("=" * 60)
    if not apk_path.is_file():
        print(f"Notice: APK not found at {apk_path}")
        return None
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            manifest_bytes = z.read("AndroidManifest.xml")
            # Extract printable package names
            matches = re.findall(rb"ml\.docilealligator[a-zA-Z0-9_\.]+", manifest_bytes)
            if matches:
                pkg = matches[0].decode("utf-8", errors="ignore")
                print(f"Detected APK Package Name: {pkg}")
                return pkg
            else:
                print("Could not find ml.docilealligator package string in binary manifest.")
    except Exception as e:
        print(f"Error inspecting APK: {e}")
    return None

def inspect_mpp(mpp_file: Path):
    print("\n" + "=" * 60)
    print(f"Inspecting built MPP bundle: {mpp_file.name}")
    print(f"Path: {mpp_file.resolve()}")
    print("=" * 60)

    with zipfile.ZipFile(mpp_file, "r") as z:
        entries = z.namelist()
        print(f"\nTotal files inside .mpp archive: {len(entries)}")
        for name in entries:
            info = z.getinfo(name)
            print(f"  - {name} ({info.file_size:,} bytes)")

        # Verify critical DEX entries
        has_dex = "classes.dex" in entries
        print(f"\nHas 'classes.dex': {'YES' if has_dex else 'NO'}")
        
        # Read DEX to verify Infinity class bytecode was compiled into classes.dex
        if has_dex:
            dex_data = z.read("classes.dex")
            dex_text = dex_data.decode("latin1", errors="ignore")
            
            print("\nBytecode Verification in classes.dex:")
            classes_to_check = [
                ("Infinity FixSLinksPatch", "Lapp/morphe/patches/reddit/customclients/infinity/misc/FixSLinksPatch"),
                ("Infinity FixRedgifsApiPatch", "Lapp/morphe/patches/reddit/customclients/infinity/misc/FixRedgifsApiPatch"),
                ("Infinity UseUserEndpointPatch", "Lapp/morphe/patches/reddit/customclients/infinity/misc/UseUserEndpointPatch"),
                ("Infinity SpoofClientPatch", "Lapp/morphe/patches/reddit/customclients/infinity/api/SpoofClientPatch"),
                ("Infinity Extension APIUtils", "Lapp/morphe/extension/infinity/APIUtils;"),
            ]
            for label, pattern in classes_to_check:
                present = pattern in dex_text
                status = "FOUND" if present else "MISSING"
                print(f"  [{status}] {label} ({pattern})")

def inspect_patch_catalog(patches_list_path: Path, detected_pkg: str | None = None):
    print("\n" + "=" * 60)
    print(f"Inspecting Patch Catalog ({patches_list_path.name})")
    print("=" * 60)

    if not patches_list_path.is_file():
        print(f"patches-list.json not found at {patches_list_path}")
        return

    data = json.loads(patches_list_path.read_text(encoding="utf-8"))
    patches = data.get("patches", [])
    print(f"Total patches in bundle: {len(patches)}")

    # Search for all patches supporting Infinity
    infinity_pkg = "ml.docilealligator.infinityforreddit.plus"
    patreon_pkg = "ml.docilealligator.infinityforreddit.patreon"

    infinity_patches = []
    for patch in patches:
        name = patch.get("name", "")
        packages = [
            cp.get("packageName")
            for cp in (patch.get("compatiblePackages") or [])
        ]
        if infinity_pkg in packages or patreon_pkg in packages:
            infinity_patches.append((name, patch.get("category"), packages))

    print(f"\nFound {len(infinity_patches)} patches compatible with Infinity:")
    for idx, (name, cat, pkgs) in enumerate(infinity_patches, 1):
        print(f"  {idx}. [{cat}] {name}")
        for pkg in pkgs:
            if "infinity" in pkg:
                print(f"      -> {pkg}")

    print("\n" + "=" * 60)
    print("Compatibility Summary:")
    print("=" * 60)
    if detected_pkg:
        matched = [name for name, _, pkgs in infinity_patches if detected_pkg in pkgs]
        print(f"Target APK ({detected_pkg}) matches {len(matched)} patches:")
        for name in matched:
            print(f"  * {name}")
    else:
        print(f"Ready for: {infinity_pkg} and {patreon_pkg}")

def main():
    root = Path(__file__).resolve().parent.parent
    
    # 1. Inspect APK if present
    apk_candidates = [
        root.parent / "Infinity+-v8.3.4.apk",
        root / "Infinity+-v8.3.4.apk",
    ]
    detected_pkg = None
    for cand in apk_candidates:
        if cand.is_file():
            detected_pkg = inspect_apk(cand)
            break

    # 2. Find built MPP
    mpp_files = list(root.glob("patches/build/libs/patches-*.mpp"))
    if not mpp_files:
        print("\nNotice: No built .mpp found in patches/build/libs/.")
        print("Build it first using: .\\gradlew :patches:buildAndroid generatePatchesList")
        sys.exit(1)

    mpp_file = mpp_files[0]
    inspect_mpp(mpp_file)

    # 3. Inspect catalog
    catalog_path = root / "patches-list.json"
    inspect_patch_catalog(catalog_path, detected_pkg)

if __name__ == "__main__":
    main()
