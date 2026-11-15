"""The source builder rejects unpinned inputs before executing downloads/code."""
import importlib.util
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import json
import plistlib
import shutil

ROOT = Path(__file__).resolve().parents[1]


class BuilderCLI(unittest.TestCase):
    def test_one_documented_entry_point_exists(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/build-lair.py'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--expected-commit', result.stdout)
        self.assertIn('--lair-profile', result.stdout)


class BuilderPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('build_lair', ROOT / 'scripts/build-lair.py')
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)

    def test_wrong_download_hash_is_rejected_even_for_a_cached_file(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'download'
            file.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                self.builder.checked_hash(file, '0' * 64)

    def test_source_identity_and_clean_tree_are_both_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
            git('init', '-q'); (root / 'code').write_text('approved')
            git('add', 'code')
            git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
            commit = git('rev-parse', 'HEAD')
            self.builder.validate_source(root, commit)
            with self.assertRaisesRegex(ValueError, 'commit'):
                self.builder.validate_source(root, '0' * 40)
            (root / 'code').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'dirty'):
                self.builder.validate_source(root, commit)

    def test_incomplete_isolation_results_never_admit_a_build(self):
        good = dict(successful=True, tests_run=11, failures=0, errors=0, skipped=0)
        self.builder.validate_tests(good)
        for patch in [dict(successful=False), dict(tests_run=10), dict(failures=1),
                      dict(errors=1), dict(skipped=1), dict(successful='yes')]:
            with self.subTest(patch=patch), self.assertRaisesRegex(ValueError, 'isolation'):
                self.builder.validate_tests({**good, **patch})

    def test_receipt_hashes_bind_the_built_files(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder)
            file = app / 'Contents/MacOS/kiri'; file.parent.mkdir(parents=True); file.write_bytes(b'engine')
            digest = hashlib.sha256(b'engine').hexdigest()
            self.builder.verify_files(app, {'Contents/MacOS/kiri': digest})
            file.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                self.builder.verify_files(app, {'Contents/MacOS/kiri': digest})

    @unittest.skipUnless(sys.platform == 'darwin', 'requires real macOS code signing')
    def test_receipt_binds_the_final_signed_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / 'Example.app'
            for name in self.builder.FILES:
                file = app / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(b'fixture')
            shutil.copyfile('/usr/bin/true', app / 'Contents/MacOS/kiri')
            (app / 'Contents/MacOS/kiri').chmod(0o755)
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(dict(
                CFBundleIdentifier='dev.kiri.app.lair', CFBundleExecutable='kiri', CFBundlePackageType='APPL')))
            self.builder.seal(app, {'schema': 1, 'source_commit': 'a' * 40}, None)
            receipt = json.loads(Path(str(app) + '.build.json').read_text())
            self.builder.verify_files(app, receipt['files'])
            self.assertNotIn('files', json.loads((app / 'Contents/Resources/lair-build.json').read_text()))
