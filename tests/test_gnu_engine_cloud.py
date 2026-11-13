"""Cloud-stage guard/receipt tests; no cloud VM, download or compiler is run."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('gnu_cloud_tests', ROOT / 'tools/ci/gnu-engine-cloud.py')
CLOUD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLOUD)


class CloudBuildTests(unittest.TestCase):
    def test_local_or_proot_session_is_not_a_hosted_cloud_job(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'GitHub-hosted'):
                CLOUD.require_vm()

    def test_root_is_not_admitted_for_source_building(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                       'GITHUB_WORKSPACE': str(ROOT)}
        with patch.dict(os.environ, environment), patch.object(CLOUD.platform, 'system', return_value='Linux'), \
                patch.object(CLOUD.platform, 'machine', return_value='aarch64'), patch.object(CLOUD.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'root is limited'):
                CLOUD.require_vm()

    def test_x86_runner_does_not_silently_select_emulation(self):
        environment = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                       'GITHUB_WORKSPACE': str(ROOT)}
        with patch.dict(os.environ, environment), patch.object(CLOUD.platform, 'machine', return_value='x86_64'), \
                patch.object(CLOUD.os, 'geteuid', return_value=1001):
            with self.assertRaises(RuntimeError):
                CLOUD.require_vm()

    def test_insufficient_memory_is_reported_before_compilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            with patch.object(CLOUD, 'EVIDENCE', evidence), patch.object(CLOUD, 'require_vm'), \
                    patch.object(CLOUD, 'resources', return_value={'memoryBytes': 8 * 1024 ** 3, 'disk': {'free': 100 * 1024 ** 3}}):
                with self.assertRaisesRegex(RuntimeError, '12 GiB'):
                    CLOUD.preflight()
            self.assertFalse(json.loads((evidence / 'host.json').read_text())['androidExecuted'])

    def test_insufficient_disk_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(CLOUD, 'EVIDENCE', Path(temporary)), patch.object(CLOUD, 'require_vm'), \
                    patch.object(CLOUD, 'resources', return_value={'memoryBytes': 16 * 1024 ** 3, 'disk': {'free': 1024}}):
                with self.assertRaisesRegex(RuntimeError, '20 GiB'):
                    CLOUD.preflight()

    def test_state_pointer_cannot_read_an_unrelated_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / 'work'
            work.mkdir()
            unrelated = root / 'unrelated.json'
            unrelated.write_text('{}')
            (work / 'engine-state.txt').write_text(str(unrelated))
            with patch.object(CLOUD, 'ROOT', root), patch.object(CLOUD, 'WORK', work):
                with self.assertRaisesRegex(ValueError, 'leaves'):
                    CLOUD.state_path()


if __name__ == '__main__':
    unittest.main()
