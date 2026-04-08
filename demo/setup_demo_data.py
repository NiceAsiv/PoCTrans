"""Setup demo data - copy CVE-2024-1597 data from reference project and seed memory."""

import shutil
import json
from pathlib import Path

project_root = Path(__file__).parent.parent.resolve()
ref_dir = project_root / "ref" / "PoCAdaptation"


def setup():
    print("Setting up demo data for CVE-2024-1597...")

    # 1. Copy origin PoC
    origin_src = ref_dir / "Origin" / "CVE-2024-1597" / "exploit"
    origin_dst = project_root / "data" / "origin" / "CVE-2024-1597" / "exploit"
    if origin_src.exists():
        if origin_dst.exists():
            shutil.rmtree(origin_dst)
        shutil.copytree(origin_src, origin_dst)
        print(f"  ✓ Copied origin PoC -> {origin_dst}")
    else:
        print(f"  ✗ Origin PoC not found: {origin_src}")
        return

    # 2. Copy diff data
    diff_src = ref_dir / "library" / "diff" / "CVE-2024-1597"
    diff_dst = project_root / "data" / "diffs" / "CVE-2024-1597"
    if diff_src.exists():
        if diff_dst.exists():
            shutil.rmtree(diff_dst)
        shutil.copytree(diff_src, diff_dst)
        print(f"  ✓ Copied diffs -> {diff_dst}")
    else:
        print(f"  ! No pre-computed diffs found (will need to generate)")
        diff_dst.mkdir(parents=True, exist_ok=True)

    # 3. Copy version list cache
    lib_src = ref_dir / "library" / "org_postgresql_postgresql.txt"
    lib_dst = project_root / "data" / "library" / "org_postgresql_postgresql.txt"
    if lib_src.exists():
        lib_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(lib_src, lib_dst)
        print(f"  ✓ Copied version list -> {lib_dst}")

    # 4. Create CVE config
    cve_config = [
        {
            "CVE": "CVE-2024-1597",
            "groupId": "org.postgresql",
            "artifactId": "postgresql",
            "exploitableVersion": "9.4.1212",
            "runtimeEnvironment": "11",
            "reproducedBehavior": "org.junit.ComparisonFailure",
            "reproducedDetail": ["int", "[1 ,2 ,3 ,4]"],
            "affected": [
                "9.2-1002-jdbc4", "9.2-1003-jdbc3", "9.2-1003-jdbc4",
                "9.2-1004-jdbc3", "9.2-1004-jdbc4", "9.2-1004-jdbc41",
                "9.3-1100-jdbc3", "9.3-1100-jdbc4", "9.3-1100-jdbc41",
                "9.4.1207", "9.4.1208", "9.4.1209", "9.4.1210", "9.4.1211", "9.4.1212"
            ],
            "requiredAdaptVersions": [
                "9.2-1002-jdbc4", "9.2-1003-jdbc3", "9.2-1003-jdbc4",
                "9.2-1004-jdbc3", "9.2-1004-jdbc4", "9.2-1004-jdbc41",
                "9.3-1100-jdbc3", "9.3-1100-jdbc4", "9.3-1100-jdbc41"
            ]
        }
    ]

    config_path = project_root / "data" / "cves.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cve_config, f, indent=2, ensure_ascii=False)
    print(f"  ✓ Created CVE config -> {config_path}")

    # 5. Seed memory from reference adapted versions
    _seed_memory_from_ref()

    # 6. Create workspace and logs directories
    (project_root / "workspace").mkdir(exist_ok=True)
    (project_root / "logs").mkdir(exist_ok=True)
    (project_root / "logs" / "traces").mkdir(exist_ok=True)
    print(f"  ✓ Created workspace and logs directories")

    print("\nSetup complete!")
    print("  Test tools: python demo/test_tools.py")
    print("  Run demo:   python demo/run_demo.py")


def _seed_memory_from_ref():
    """Seed memory store with a known successful adaptation from the reference project."""
    adapted_dir = ref_dir / "Adapted" / "CVE-2024-1597"
    if not adapted_dir.exists():
        print("  ! No reference adaptations found for memory seeding")
        return

    memory_dir = project_root / "data" / "memory" / "CVE-2024-1597"
    memory_dir.mkdir(parents=True, exist_ok=True)

    # Pick a representative adapted version to seed as memory
    # Use 9.3-1100-jdbc4 as it's a mid-range version
    seed_versions = ["9.3-1100-jdbc4", "9.2-1002-jdbc4"]
    seeded = 0

    for version in seed_versions:
        adapted_poc = adapted_dir / version / "exploit"
        if not adapted_poc.exists():
            continue

        # Read adapted code
        adapted_code = {}
        for java_file in adapted_poc.rglob("*.java"):
            rel = java_file.relative_to(adapted_poc)
            adapted_code[str(rel)] = java_file.read_text(encoding="utf-8", errors="replace")

        pom_file = adapted_poc / "pom.xml"
        if pom_file.exists():
            adapted_code["pom.xml"] = pom_file.read_text(encoding="utf-8", errors="replace")

        record = {
            "base_version": "9.4.1212",
            "target_version": version,
            "summary": (
                f"Successfully migrated PoC from 9.4.1212 to {version}. "
                "Key changes: package path v3->v2, constructor parameter "
                "TypeTransferModeRegistry->boolean, toString() replaced with "
                "toString(int) + manual StringBuilder concatenation, "
                "removed TypeTransferModeRegistry import and field."
            ),
            "adapted_code": adapted_code
        }

        record_file = memory_dir / f"9.4.1212_to_{version}.json"
        record_file.write_text(
            json.dumps(record, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        seeded += 1

    print(f"  ✓ Seeded {seeded} migration memories from reference project")


if __name__ == "__main__":
    setup()
