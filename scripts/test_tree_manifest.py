#!/usr/bin/env python3
"""Behavior tests on synthetic temporary files; no real workspace mutations."""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import tree_manifest as tool


class TreeManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="workspace-migration-test-")
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "旧 工作区"
        self.root.mkdir()
        self.evidence = self.base / "private evidence"
        self.evidence.mkdir()
        self.manifest = self.evidence / "before.json"
        self.report = self.evidence / "after.json"
        (self.root / "说明.md").write_text("合成资料\n", encoding="utf-8")
        (self.root / "空目录").mkdir()
        (self.root / ".git/refs/local").mkdir(parents=True)
        (self.root / ".git/refs/local/temporary").write_bytes(b"synthetic-reference")
        self.addCleanup(self.temporary.cleanup)

    def test_capture_and_verify_after_same_parent_rename(self):
        captured = tool.capture(self.root, self.manifest)
        self.assertEqual(captured["counts"]["files"], 2)
        self.assertIn("空目录", captured["directories"])
        self.assertIn(".git/refs/local/temporary", [row["path"] for row in captured["files"]])
        archive = self.base / "归档 工作区"
        self.assertEqual(self.root.resolve().parent, self.base)
        self.assertEqual(archive.parent.resolve(), self.base)
        self.assertFalse(archive.exists())
        self.root.rename(archive)
        result = tool.verify(archive, self.manifest, self.report)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["verifiedRoot"], str(archive))
        self.assertFalse(self.root.exists())

    def test_same_size_edit_detected_even_with_restored_mtime(self):
        file = self.root / "payload"
        file.write_bytes(b"first")
        before = file.stat()
        tool.capture(self.root, self.manifest)
        file.write_bytes(b"other")
        os.utime(file, ns=(before.st_atime_ns, before.st_mtime_ns))
        result = tool.verify(self.root, self.manifest, self.report)
        self.assertEqual(result["differences"]["filesChanged"], ["payload"])
        self.assertEqual(result["status"], "mismatch")

    def test_add_remove_empty_directory_and_git_changes_are_not_ignored(self):
        tool.capture(self.root, self.manifest)
        (self.root / "说明.md").unlink()
        (self.root / "新增").write_bytes(b"new")
        (self.root / "空目录").rmdir()
        (self.root / "新空目录").mkdir()
        (self.root / ".git/refs/local/temporary").write_bytes(b"changed")
        differences = tool.verify(self.root, self.manifest, self.report)["differences"]
        self.assertEqual(differences["filesAdded"], ["新增"])
        self.assertEqual(differences["filesRemoved"], ["说明.md"])
        self.assertEqual(differences["filesChanged"], [".git/refs/local/temporary"])
        self.assertEqual(differences["directoriesAdded"], ["新空目录"])
        self.assertEqual(differences["directoriesRemoved"], ["空目录"])

    def test_empty_tree_can_be_captured(self):
        empty = self.base / "empty"
        empty.mkdir()
        result = tool.capture(empty, self.manifest)
        self.assertEqual(result["counts"], {"files": 0, "directories": 0, "bytes": 0})
        self.assertEqual(tool.verify(empty, self.manifest, self.report)["status"], "matched")

    def test_existing_output_is_never_overwritten(self):
        self.manifest.write_bytes(b"keep-original")
        with self.assertRaisesRegex(tool.ManifestError, "OUTPUT_ALREADY_EXISTS"):
            tool.capture(self.root, self.manifest)
        self.assertEqual(self.manifest.read_bytes(), b"keep-original")

    def test_report_is_not_overwritten(self):
        tool.capture(self.root, self.manifest)
        self.report.write_bytes(b"keep-report")
        with self.assertRaisesRegex(tool.ManifestError, "OUTPUT_ALREADY_EXISTS"):
            tool.verify(self.root, self.manifest, self.report)
        self.assertEqual(self.report.read_bytes(), b"keep-report")

    def test_output_inside_source_is_rejected_without_writing(self):
        output = self.root / "manifest.json"
        with self.assertRaisesRegex(tool.ManifestError, "EVIDENCE_MUST_BE_OUTSIDE_TREE"):
            tool.capture(self.root, output)
        self.assertFalse(output.exists())

    def test_relative_paths_cannot_depend_on_launcher_cwd(self):
        with self.assertRaisesRegex(tool.ManifestError, "ABSOLUTE_PATH_REQUIRED"):
            tool.capture("relative-root", self.manifest)
        with self.assertRaisesRegex(tool.ManifestError, "ABSOLUTE_PATH_REQUIRED"):
            tool.capture(self.root, "relative-manifest.json")

    def test_source_change_during_chunk_read_is_rejected(self):
        file = self.root / "large.bin"
        file.write_bytes(b"x" * (tool.CHUNK_SIZE * 2 + 1))
        changed = False

        def progress(files, size):
            nonlocal changed
            if size > tool.CHUNK_SIZE and not changed:
                changed = True
                with file.open("ab") as stream:
                    stream.write(b"changed")

        with self.assertRaisesRegex(tool.ManifestError, "TREE_CHANGED_DURING_SCAN"):
            tool.capture(self.root, self.manifest, progress)
        self.assertTrue(changed)
        self.assertFalse(self.manifest.exists())

    def test_change_to_previously_hashed_file_is_rejected(self):
        original = tool._hash_file
        changed = False

        def mutate(path, expected, advance):
            nonlocal changed
            value = original(path, expected, advance)
            if not changed:
                path.write_bytes(b"new-content-after-read")
                changed = True
            return value

        with patch.object(tool, "_hash_file", side_effect=mutate):
            with self.assertRaisesRegex(tool.ManifestError, "TREE_CHANGED_DURING_SCAN"):
                tool.capture(self.root, self.manifest)
        self.assertFalse(self.manifest.exists())

    def test_malformed_manifest_stops_without_a_success_report(self):
        self.manifest.write_text('{"private-body":', encoding="utf-8")
        with self.assertRaisesRegex(tool.ManifestError, "INVALID_MANIFEST"):
            tool.verify(self.root, self.manifest, self.report)
        self.assertFalse(self.report.exists())

    def test_forged_manifest_paths_duplicates_and_counts_are_rejected(self):
        valid = tool.snapshot(self.root)
        mutations = [lambda v: v["files"][0].update(path="../outside"),
                     lambda v: v["files"].append(copy.deepcopy(v["files"][0])),
                     lambda v: v["counts"].update(files=True),
                     lambda v: v["directories"].remove(".git/refs")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(valid)
                mutate(value)
                with self.assertRaisesRegex(tool.ManifestError, "INVALID_MANIFEST"):
                    tool.validate_manifest(value)

    def test_metadata_only_difference_does_not_claim_content_difference(self):
        tool.capture(self.root, self.manifest)
        file = self.root / "说明.md"
        stamp = file.stat()
        os.utime(file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns - 10_000_000_000))
        self.assertEqual(tool.verify(self.root, self.manifest, self.report)["status"], "matched")

    def test_symlink_root_children_and_output_ancestors_are_rejected(self):
        target = self.base / "linked-target"
        target.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("OS account cannot create symlinks; junction has a separate Windows test")
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.snapshot(self.root)
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.snapshot(link)
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.capture(target, link / "out.json")
        self.assertFalse((target / "out.json").exists())

    @unittest.skipUnless(os.name == "nt", "Windows junction behavior")
    def test_windows_junction_is_rejected(self):
        target = self.base / "junction-target"
        target.mkdir()
        junction = self.root / "junction"
        self.assertTrue(target.resolve().is_relative_to(self.base))
        self.assertTrue(junction.parent.resolve().is_relative_to(self.base))
        command = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
        created = subprocess.run([str(command), "/d", "/c", "mklink", "/J", str(junction), str(target)],
                                 capture_output=True, check=False)
        self.assertEqual(created.returncode, 0)
        self.addCleanup(lambda: junction.rmdir() if junction.exists() else None)
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.snapshot(self.root)
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.snapshot(junction)
        with self.assertRaisesRegex(tool.ManifestError, "LINK_OR_REPARSE_POINT"):
            tool.capture(target, junction / "out.json")
        self.assertFalse((target / "out.json").exists())

    def test_cli_from_unrelated_cwd_and_minimal_path_preserves_exit_codes(self):
        script = Path(tool.__file__).resolve()
        environment = dict(os.environ)
        environment["PATH"] = str(Path(os.environ.get("SystemRoot", "/")) / "System32") if os.name == "nt" else "/usr/bin:/bin"
        arguments = [sys.executable, "-X", "utf8", str(script)]

        def run(*args):
            return subprocess.run([*arguments, *map(str, args)], cwd=self.evidence, env=environment,
                                  capture_output=True, text=True, encoding="utf-8", check=False)

        captured = run("capture", "--root", self.root, "--manifest", self.manifest)
        self.assertEqual(captured.returncode, 0, captured.stdout)
        self.assertEqual(json.loads(captured.stdout)["status"], "captured")
        (self.root / "PRIVATE_NAME_CANARY").write_bytes(b"PRIVATE_CONTENT_CANARY")
        checked = run("verify", "--root", self.root, "--manifest", self.manifest, "--report", self.report)
        self.assertEqual(checked.returncode, 1)
        self.assertEqual(json.loads(checked.stdout)["status"], "mismatch")
        self.assertNotIn("PRIVATE_", checked.stdout + checked.stderr)
        self.assertNotIn(str(self.root), checked.stdout + checked.stderr)
        failed = run("capture", "--root", self.root, "--manifest", self.manifest)
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(json.loads(failed.stdout)["code"], "OUTPUT_ALREADY_EXISTS")

    def test_failure_output_does_not_echo_paths_or_exception_messages(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = tool.main(["capture", "--root", str(self.base / "PRIVATE_PATH_CANARY"),
                              "--manifest", str(self.manifest)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {"status": "stopped", "code": "PATH_UNAVAILABLE"})
        self.assertNotIn("PRIVATE_", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
