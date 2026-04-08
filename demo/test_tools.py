"""Tool unit tests - verify each tool works correctly before running the agent."""

import json
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(project_root))

from poctrans.tools import diff_viewer, maven_runner, code_editor, error_parser, version_manager
from poctrans.memory import MemoryStore
from poctrans.config import DATA_DIR, WORKSPACE_DIR


def test_diff_viewer():
    print("=" * 50)
    print("TEST: diff_viewer")
    print("=" * 50)

    # List available diffs
    diffs = diff_viewer.list_available_diffs("CVE-2024-1597")
    print(f"  Available diffs: {diffs}")

    if diffs:
        # Parse a diff file name to get versions
        name = diffs[0].replace(".diff", "")
        parts = name.split("-", 1) if "-" in name else name.rsplit("-", 1)
        # Try the first available diff
        summary = diff_viewer.view_diff_summary(
            "CVE-2024-1597",
            "9.4.1208.jre7", "9.4.1209"
        )
        print(f"  Diff summary (first 300 chars):\n{summary[:300]}")

        # Search diff
        result = diff_viewer.search_diff(
            "CVE-2024-1597", "9.4.1208.jre7", "9.4.1209",
            "SimpleParameterList"
        )
        print(f"\n  Search 'SimpleParameterList' (first 300 chars):\n{result[:300]}")
    else:
        print("  [SKIP] No diffs available")

    # Test missing diff
    result = diff_viewer.view_diff("CVE-2024-1597", "9.4.1212", "9.2-1002-jdbc4")
    print(f"\n  Missing diff result: {result[:100]}")
    print("  PASS\n")


def test_code_editor():
    print("=" * 50)
    print("TEST: code_editor")
    print("=" * 50)

    origin_dir = DATA_DIR / "origin" / "CVE-2024-1597" / "exploit"
    if not origin_dir.exists():
        print("  [SKIP] Origin PoC not found")
        return

    # List files
    files = code_editor.list_project_files(origin_dir)
    print(f"  Project files:\n{files}")

    # Read Java file
    java_files = code_editor.find_java_files(origin_dir)
    print(f"\n  Java files: {[str(f.name) for f in java_files]}")

    if java_files:
        content = code_editor.read_file(java_files[0])
        print(f"\n  Java content (first 200 chars):\n{content[:200]}")

    # Find pom
    pom = code_editor.find_pom_file(origin_dir)
    print(f"\n  pom.xml: {pom}")
    print("  PASS\n")


def test_error_parser():
    print("=" * 50)
    print("TEST: error_parser")
    print("=" * 50)

    # Fake Maven log with compilation error
    fake_log = """[INFO] --- maven-compiler-plugin:3.1:compile ---
[ERROR] /workspace/src/test/java/edu/vision/se/Testcase1.java:[10,45] error: cannot find symbol
  symbol:   class TypeTransferModeRegistry
  location: package org.postgresql.core.v3
[INFO] BUILD FAILURE
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.1:compile
Tests run: 0, Failures: 0, Errors: 0, Skipped: 0"""

    errors = error_parser.parse_maven_errors(fake_log)
    print(f"  Parsed errors: {len(errors)}")
    for e in errors:
        print(f"    - [{e.error_type}] {e.file}:{e.line} {e.message}")

    classification = error_parser.classify_failure(fake_log)
    print(f"  Classification: {classification}")

    summary = error_parser.extract_error_summary(fake_log)
    print(f"  Error summary:\n{summary}")

    # Test with test failure log
    test_fail_log = """Tests run: 1, Failures: 1, Errors: 0, Skipped: 0
org.junit.ComparisonFailure: Expected string representation of values does not match
  expected:<[('1'::int4)]> but was:<[1]>
[INFO] BUILD FAILURE"""

    classification2 = error_parser.classify_failure(test_fail_log)
    print(f"\n  Test failure classification: {classification2}")
    print("  PASS\n")


def test_version_manager():
    print("=" * 50)
    print("TEST: version_manager")
    print("=" * 50)

    # Test version list loading from cache
    versions = version_manager.fetch_maven_versions(
        "org.postgresql", "postgresql"
    )
    print(f"  Cached versions: {len(versions)} (first 5: {versions[:5]})")

    # Test nearest version selection
    reproduced = ["9.4.1212"]
    pending = ["9.2-1002-jdbc4", "9.4.1211", "9.4.1210"]
    result = version_manager.select_nearest_version(pending, reproduced, versions)
    print(f"  Nearest version to 9.4.1212: {result}")
    print("  PASS\n")


def test_memory():
    print("=" * 50)
    print("TEST: memory")
    print("=" * 50)

    store = MemoryStore()

    # Test recall with no data
    result = store.recall("CVE-9999-0000")
    print(f"  Empty recall: {result[:100]}")

    # Test save and recall
    store.save(
        cve_id="CVE-TEST-0001",
        base_version="1.0",
        target_version="2.0",
        summary="Changed package v1 to v2",
        adapted_code={"src/test/Test.java": "public class Test {}"}
    )
    result = store.recall("CVE-TEST-0001", "1.0", "2.0")
    print(f"  Recalled memory (first 200 chars):\n{result[:200]}")

    # Cleanup test data
    import shutil
    test_dir = DATA_DIR / "memory" / "CVE-TEST-0001"
    if test_dir.exists():
        shutil.rmtree(test_dir)

    print("  PASS\n")


def test_docker_maven():
    print("=" * 50)
    print("TEST: maven_runner (Docker)")
    print("=" * 50)

    origin_dir = DATA_DIR / "origin" / "CVE-2024-1597" / "exploit"
    if not origin_dir.exists():
        print("  [SKIP] Origin PoC not found")
        return

    # Test workspace preparation
    workspace = maven_runner.prepare_poc_workspace(origin_dir, "CVE-TEST", "test-version")
    print(f"  Workspace created: {workspace}")
    assert workspace.exists()

    # Test Maven execution in Docker
    print("  Running mvn test in Docker (this may take ~30s)...")
    success, log_text = maven_runner.run_poc_test("CVE-TEST", "test-version", workspace)
    print(f"  Execution completed: success={success}")

    # Test verification
    verified, report = maven_runner.verify_reproduction(
        log_text,
        "org.junit.ComparisonFailure",
        ["int", "[1 ,2 ,3 ,4]"]
    )
    print(f"  Verification: {verified}")
    print(f"  Report:\n{report}")

    # Cleanup
    import shutil
    test_ws = WORKSPACE_DIR / "CVE-TEST"
    if test_ws.exists():
        shutil.rmtree(test_ws)

    print("  PASS\n")


if __name__ == "__main__":
    print("\nPoCTrans Tool Tests\n")

    test_diff_viewer()
    test_code_editor()
    test_error_parser()
    test_version_manager()
    test_memory()

    # Docker test is optional (slow)
    if "--with-docker" in sys.argv:
        test_docker_maven()
    else:
        print("  [SKIP] Docker test (run with --with-docker to include)\n")

    print("All tests passed!")
