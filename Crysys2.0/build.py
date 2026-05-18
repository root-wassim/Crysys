#!/usr/bin/env python3
"""
build.py — Crysys 2.0 C Engine Compiler
Compiles all C source files from engine/ into crysys_cli.exe
"""
import os
import glob
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def collect_sources():
    patterns = [
        os.path.join(BASE_DIR, "engine", "core",    "*.c"),
        os.path.join(BASE_DIR, "engine", "classic",  "*.c"),
        os.path.join(BASE_DIR, "engine", "modern",   "*.c"),
        os.path.join(BASE_DIR, "engine", "hash",     "*.c"),
        os.path.join(BASE_DIR, "main.c"),
    ]
    sources = []
    for pattern in patterns:
        found = glob.glob(pattern)
        if not found:
            print(f"  [WARNING] No files for: {pattern}")
        sources.extend(found)
    return sources


def build():
    print("\n" + "=" * 55)
    print("  Crysys 2.0 - Building C Encryption Engine")
    print("=" * 55)
    sources = collect_sources()
    if not sources:
        print("[ERROR] No source files found. Aborting.")
        sys.exit(1)
    print(f"  Found {len(sources)} source files.")
    output = os.path.join(BASE_DIR, "engine", "crysys_cli.exe")
    cmd = [
        "gcc", "-Wall", "-Wextra", "-O2",
        f"-I{BASE_DIR}",
        f"-I{os.path.join(BASE_DIR, 'engine', 'core')}",
    ] + sources + ["-o", output, "-lm"]
    print(f"  Output: {output}\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.returncode == 0:
        size_kb = os.path.getsize(output) // 1024
        print(f"\n  [SUCCESS] crysys_cli.exe compiled ({size_kb} KB)")
        return True
    else:
        print(f"\n  [ERROR] Compilation failed (exit code {result.returncode})")
        if result.stderr:
            print(result.stderr)
        return False


if __name__ == "__main__":
    success = build()
    sys.exit(0 if success else 1)
