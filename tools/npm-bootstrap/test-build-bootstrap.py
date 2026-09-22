#!/usr/bin/env python3
"""Pure generation/drift controls; never execute npm or the generated bundle."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('npm_bootstrap_builder', HERE / 'build-bootstrap.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class BootstrapGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tirith-bootstrap-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        target = self.root / builder.SOURCES
        target.mkdir(parents=True)
        for _, name in builder.PARTS:
            shutil.copyfile(HERE / name, target / name)
        (self.root / builder.GENERATED).parent.mkdir(parents=True)
        for path, content in builder.outputs(self.root):
            path.write_bytes(content)

    def test_exact_generated_product_and_repeatability(self):
        first = builder.build_bundle(HERE)
        self.assertEqual(first, builder.build_bundle(HERE))
        self.assertEqual(hashlib.sha256(first[0]).hexdigest(),
                         '41183108651b825e4712922f9056d1caf5766814f992167ac36fd200d9daa4d7')
        builder.check(self.root)

    def test_changed_module_cannot_pass_old_bundle_or_manifest(self):
        source = self.root / builder.SOURCES / 'bindings.cjs'
        source.write_bytes(source.read_bytes() + b'\n// edited\n')
        with self.assertRaisesRegex(ValueError, 'generated bootstrap drift'):
            builder.check(self.root)

    def test_tampered_generated_bytes_and_manifest_refuse(self):
        for relative in [builder.GENERATED, builder.SOURCES / 'source-hashes.json']:
            with self.subTest(path=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaisesRegex(ValueError, 'generated bootstrap drift'):
                    builder.check(self.root)
                path.write_bytes(original)

    def test_missing_output_refuses_without_regenerating(self):
        generated = self.root / builder.GENERATED
        generated.unlink()
        with self.assertRaisesRegex(ValueError, 'generated bootstrap drift'):
            builder.check(self.root)
        self.assertFalse(generated.exists())

    def test_oversized_or_invalid_utf8_module_refuses(self):
        source = self.root / builder.SOURCES / 'bindings.cjs'
        for content in [b'x' * (builder.MAX_SOURCE_BYTES + 1), b'\xff']:
            source.write_bytes(content)
            with self.assertRaises((ValueError, UnicodeError)):
                builder.build_bundle(source.parent)

    def test_module_symlink_refuses(self):
        source = self.root / builder.SOURCES / 'bindings.cjs'
        saved = source.with_suffix('.saved')
        source.rename(saved)
        try:
            source.symlink_to(saved.name)
        except OSError as error:
            self.skipTest(f'host cannot create symlink: {error}')
        with self.assertRaisesRegex(ValueError, 'invalid bounded bootstrap source'):
            builder.build_bundle(source.parent)

    def test_unlisted_file_cannot_enter_bundle(self):
        before = builder.build_bundle(self.root / builder.SOURCES)
        (self.root / builder.SOURCES / 'unapproved.cjs').write_text('throw new Error("unapproved")')
        self.assertEqual(builder.build_bundle(self.root / builder.SOURCES), before)


if __name__ == '__main__':
    unittest.main()
