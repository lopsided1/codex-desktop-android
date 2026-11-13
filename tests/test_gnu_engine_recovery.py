"""Real Git patch isolation tests; no Rust build or device execution."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery_builder", ROOT / "tools/executor/build-gnu-engine.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class RecoveryIsolationTests(unittest.TestCase):
    def test_nested_repository_patch_applies_without_touching_parent_index(self):
        parent = ROOT / "work/recovery-patch-tests"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            root = Path(temporary)
            def git(*args, cwd=root):
                return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()
            git("init", "-q")
            (root / "parent-marker").write_text("parent data\n")
            git("add", "parent-marker")
            index = (root / ".git/index").read_bytes()
            author = root / "author"
            author.mkdir()
            git("init", "-q", cwd=author)
            (author / "file.txt").write_text("before\n")
            git("add", "file.txt", cwd=author)
            (author / "file.txt").write_text("after\n")
            (author / "new.txt").write_text("added\n")
            git("add", "-N", "new.txt", cwd=author)
            patch = root / "input.patch"
            patch.write_text(git("diff", "--full-index", "--binary", cwd=author) + "\n")
            snapshot = root / "nested/build/source"
            snapshot.mkdir(parents=True)
            (snapshot / "file.txt").write_text("before\n")
            builder.apply_recovery_patch(snapshot, patch)
            self.assertEqual((snapshot / "file.txt").read_text(), "after\n")
            self.assertEqual((snapshot / "new.txt").read_text(), "added\n")
            self.assertEqual((root / ".git/index").read_bytes(), index)
            self.assertFalse((snapshot / ".git").exists())
            self.assertEqual((root / "parent-marker").read_text(), "parent data\n")

    def test_false_postimage_blob_is_refused(self):
        parent = ROOT / "work/recovery-patch-tests"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file").write_text("old\n")
            old = subprocess.check_output(["git", "hash-object", str(source / "file")], text=True).strip()
            patch = root / "input.patch"
            patch.write_text("diff --git a/file b/file\nindex " + old + ".." + "1" * 40
                             + " 100644\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n")
            with self.assertRaisesRegex(RuntimeError, "result blob differs"):
                builder.apply_recovery_patch(source, patch)


if __name__ == "__main__":
    unittest.main()
