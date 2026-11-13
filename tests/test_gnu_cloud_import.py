"""Negative archive/provenance checks; fixtures never represent a real build."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('cloud_import_tests', ROOT / 'tools/executor/gnu_cloud_import.py')
CLOUD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOUD)
PINS = {'base': 'test-base', 'sha256': 'test-patch'}


def archive(*, extra=None, duplicate=False, corrupt=False, symlink=False, mode=False):
    contents = {key: b'unit-test-only' for key in ('codex', 'codex-code-mode-host', 'engine.patch',
               'recovery-manifest.json', 'SOURCES.json', 'static-compatibility.json')}
    manifest = {'kind': 'separate-gnu-engine-payload', 'target': CLOUD.TARGET,
        'sourceBase': PINS['base'], 'patchSha256': PINS['sha256'],
        'androidExecution': False, 'liveUiQualified': False,
        'files': [{'path': key, 'bytes': len(value), 'mode': 0o644,
                   'sha256': hashlib.sha256(value).hexdigest()} for key, value in contents.items()]}
    contents['manifest.json'] = json.dumps(manifest).encode()
    if extra is not None:
        contents[extra] = b'extra'
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w') as stream:
        for key, value in contents.items():
            info = tarfile.TarInfo(key)
            info.mode = 0o755 if mode and key == 'codex' else 0o644
            if symlink and key == 'codex':
                info.type, info.linkname = tarfile.SYMTYPE, '/outside'
                stream.addfile(info)
            else:
                data = b'changed-by-test' if corrupt and key == 'codex' else value
                info.size = len(data)
                stream.addfile(info, io.BytesIO(data))
        if duplicate:
            info = tarfile.TarInfo('codex')
            stream.addfile(info, io.BytesIO())
    result.seek(0)
    return tarfile.open(fileobj=result)


class CloudImportTests(unittest.TestCase):
    def test_exact_unit_fixture_is_accepted(self):
        with archive() as stream:
            manifest, members = CLOUD.package_members(stream, PINS)
        self.assertEqual(len(members), 7)
        self.assertFalse(manifest['androidExecution'])

    def test_duplicate_tar_entry_is_refused(self):
        with archive(duplicate=True) as stream, self.assertRaisesRegex(ValueError, 'Duplicate'):
            CLOUD.package_members(stream, PINS)

    def test_traversal_is_refused(self):
        with archive(extra='../outside') as stream, self.assertRaisesRegex(ValueError, 'escaping'):
            CLOUD.package_members(stream, PINS)

    def test_unindexed_file_is_refused(self):
        with archive(extra='unexpected') as stream, self.assertRaisesRegex(ValueError, 'not exact'):
            CLOUD.package_members(stream, PINS)

    def test_symlink_is_refused(self):
        with archive(symlink=True) as stream, self.assertRaisesRegex(ValueError, 'ordinary files'):
            CLOUD.package_members(stream, PINS)

    def test_corrupt_binary_is_refused(self):
        with archive(corrupt=True) as stream, self.assertRaisesRegex(ValueError, 'content differs'):
            CLOUD.package_members(stream, PINS)

    def test_mode_changes_are_refused(self):
        with archive(mode=True) as stream, self.assertRaisesRegex(ValueError, 'content differs'):
            CLOUD.package_members(stream, PINS)

    def test_in_progress_or_failed_run_is_not_a_success_receipt(self):
        for status, conclusion in (('in_progress', None), ('completed', 'failure')):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'successful conclusion'):
                CLOUD.check_run({'id': 1, 'repository': {'full_name': 'owner/repo'},
                    'head_sha': 'commit', 'status': status, 'conclusion': conclusion}, 'owner/repo', '1', 'commit')

    def test_success_on_another_commit_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            CLOUD.check_run({'id': 1, 'repository': {'full_name': 'owner/repo'}, 'head_sha': 'wrong',
                             'status': 'completed', 'conclusion': 'success'}, 'owner/repo', '1', 'commit')

    def test_duplicate_json_or_inventory_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON'):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=CLOUD.unique)
        with self.assertRaisesRegex(ValueError, 'Duplicate inventory'):
            CLOUD.indexed([{'path': 'codex'}, {'path': 'codex'}])

    def test_completion_flags_cannot_replace_import_admission_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'cloud-import.json'
            path.write_text(json.dumps({'schema': CLOUD.SCHEMA, 'sourceBase': PINS['base'],
                'patchSha256': PINS['sha256'], 'androidExecuted': False, 'inputFiles': [],
                'buildCompleted': True, 'packageCompleted': True}))
            with patch.object(CLOUD, 'recovery', return_value=PINS), self.assertRaisesRegex(ValueError, 'missing frozen'):
                CLOUD.load_import(path)


if __name__ == '__main__':
    unittest.main()
