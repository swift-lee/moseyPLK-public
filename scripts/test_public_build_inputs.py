#!/usr/bin/env python3
"""Public build boundaries using synthetic temporary inputs; never builds an APK/ZIP or uses ADB."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_client_compat as client
import build_load_probe as probe
import build_module as module
import build_registration as registration
import generate_compatibility as generator


TEXT_CONFIGS = (
    'vendor/etc/selinux/vendor_file_contexts',
    'vendor/etc/selinux/vendor_service_contexts',
    'system_ext/etc/selinux/system_ext_seapp_contexts',
    'system_ext/etc/sysconfig/hidden-api-whitelist-ext.xml',
)


class PublicBuildInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mosey-public-inputs-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / 'moseyPLK-assets'
        self.assets.mkdir()
        for target, name, value in (
                (module, 'ASSETS', self.assets),
                (module, 'ROOT', self.root),
                (generator, 'ASSETS', self.assets),
                (generator, 'BASE', self.assets / 'research/extracted/ColorOS')):
            override = patch.object(target, name, value)
            override.start()
            self.addCleanup(override.stop)

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def configurations(self):
        for relative in (*generator.RULE_FILES, *TEXT_CONFIGS):
            self.write(generator.BASE / relative, '# synthetic configuration\n')
        self.write(generator.BASE / generator.RULE_FILES[0],
                   '(type mosey_public_fixture)\n'
                   '(typeattributeset fixture_group (mosey_public_fixture))\n'
                   '(typeattributeset base_typeattr_999 (mosey_public_fixture))\n')
        self.write(generator.BASE / TEXT_CONFIGS[0], 'mosey_fixture_context\n')

    def local_module_inputs(self):
        self.configurations()
        generator.generate()
        policy = self.write(self.assets / 'restricted-inputs/sepolicy.rule', '# synthetic policy fixture\n')
        launcher = self.write(self.assets / 'research/module' / module.LAUNCHER, 'synthetic launcher data\n')
        donor_name = 'odm/bin/synthetic_donor'
        donor = self.write(self.assets / 'research/extracted/OxygenOS' / donor_name,
                           'synthetic donor data\n')
        for name, value in (
                ('SEPOLICY_SHA', module.sha(policy)),
                ('LAUNCHER_SHA', module.sha(launcher)),
                ('DONOR', {donor_name: module.sha(donor)})):
            override = patch.object(module, name, value)
            override.start()
            self.addCleanup(override.stop)
        return policy, launcher, donor

    def test_generator_writes_only_to_the_ignored_area_and_preserves_check_behavior(self):
        self.configurations()
        output = generator.generate()
        self.assertEqual(output, self.assets / 'build/generated/compatibility.sh')
        self.assertFalse((self.root / 'module-src').exists())
        content = output.read_text()
        self.assertIn('OK: 3 reviewed Mosey prerequisites', content)
        self.assertNotIn('base_typeattr_999', content)
        runnable = content
        for partition in ('vendor', 'system_ext'):
            runnable = runnable.replace('/' + partition + '/', str(generator.BASE / partition) + '/')
        good = subprocess.run(['/bin/sh'], input=runnable + '\nmosey_check_compatibility\n',
                              text=True, capture_output=True, timeout=5)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        self.write(generator.BASE / generator.RULE_FILES[0], '(type unrelated_fixture)\n')
        bad = subprocess.run(['/bin/sh'], input=runnable + '\nmosey_check_compatibility\n',
                             text=True, capture_output=True, timeout=5)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('MISSING', bad.stdout)

    def test_generator_rejects_source_tree_traversal_and_symlink_output(self):
        self.configurations()
        sentinel = self.write(self.root / 'module-src/sentinel.sh', 'unchanged\n')
        outside = self.write(self.root / 'outside.sh', 'outside\n')
        linked = self.assets / 'linked.sh'
        linked.symlink_to(outside)
        (self.assets / 'linked-parent').symlink_to(self.root, target_is_directory=True)
        for output in (sentinel, self.assets / 'build/../escape.sh', linked,
                       self.assets / 'linked-parent/output.sh'):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    generator.generate(output)
        self.assertEqual(sentinel.read_text(), 'unchanged\n')
        self.assertEqual(outside.read_text(), 'outside\n')

    def test_generator_refuses_missing_or_empty_semantics_without_overwriting_output(self):
        output = self.write(self.assets / 'build/generated/compatibility.sh', 'previous output\n')
        with self.assertRaisesRegex(SystemExit, 'Missing or empty local ColorOS'):
            generator.generate()
        self.configurations()
        for relative in (*generator.RULE_FILES, *TEXT_CONFIGS):
            self.write(generator.BASE / relative, '# synthetic configuration\n')
        with self.assertRaisesRegex(ValueError, 'empty check'):
            generator.generate()
        self.assertEqual(output.read_text(), 'previous output\n')

    def test_module_input_checks_reject_empty_placeholder_policy_and_bad_hash(self):
        policy, _, _ = self.local_module_inputs()
        inputs = module.validate_module_inputs()
        self.assertEqual(inputs['sepolicy.rule'], policy)
        self.assertIn('compatibility.sh', inputs)
        policy.write_text('')
        with self.assertRaisesRegex(SystemExit, 'Missing or empty restricted SELinux'):
            module.validate_module_inputs()
        policy.write_text('different policy\n')
        with self.assertRaisesRegex(SystemExit, 'Unexpected SHA-256'):
            module.validate_module_inputs()

    def test_module_input_checks_reject_noop_compatibility_and_symlinked_input(self):
        policy, _, donor = self.local_module_inputs()
        compatibility = self.assets / 'build/generated/compatibility.sh'
        original = compatibility.read_text()
        compatibility.write_text('mosey_check_compatibility() { return 0; }\n')
        with self.assertRaisesRegex(SystemExit, 'incomplete'):
            module.validate_module_inputs()
        compatibility.write_text(original)
        policy.unlink()
        policy.symlink_to(donor)
        with self.assertRaisesRegex(SystemExit, 'Symlinks'):
            module.validate_module_inputs()

    def test_builders_stop_before_compilation_when_restricted_inputs_are_missing(self):
        for builder in (probe, registration):
            with self.subTest(builder=builder.__name__):
                with patch.object(builder.subprocess, 'run') as run:
                    with self.assertRaisesRegex(SystemExit, 'Missing or empty generated compatibility'):
                        builder.build(self.root / 'missing-ndk')
                    run.assert_not_called()
        with self.assertRaisesRegex(SystemExit, 'historical v0.4.1 package cannot be built'):
            module.main()
        self.assertEqual(list(self.assets.iterdir()), [])

    def test_staging_uses_only_reviewed_sources_and_explicit_local_inputs(self):
        policy, _, _ = self.local_module_inputs()
        public = self.write(self.root / 'module-src/public.sh', '# reviewed public fixture\n')
        self.write(self.root / 'module-src/unreviewed.sh', '# unreviewed fixture\n')
        names = ['module-src/public.sh', 'publication-files.json']
        self.write(self.root / 'publication-files.json', json.dumps({'schema': 1, 'files': names}))
        stage = self.assets / 'build/stage'
        module.copy_public_tree('module-src', stage)
        self.assertEqual((stage / 'public.sh').read_bytes(), public.read_bytes())
        self.assertFalse((stage / 'unreviewed.sh').exists())
        module.stage_module_inputs(stage, module.validate_module_inputs())
        self.assertEqual((stage / 'sepolicy.rule').read_bytes(), policy.read_bytes())
        self.assertTrue((stage / 'compatibility.sh').is_file())

    def test_resolver_sources_use_the_public_manifest_without_a_git_index(self):
        prefix = 'client-compat/src/main/java/moseyPLK/client/'
        names = [prefix + name for name in ('GmsFixture.java', 'ResolvedGateSet.java',
                                           'Other.java', 'nested/GmsOther.java')]
        for name in names:
            self.write(self.root / name, '// synthetic public source\n')
        self.write(self.root / 'publication-files.json', json.dumps({
            'schema': 1, 'files': sorted([*names, 'publication-files.json'])}))
        with patch.object(client, 'ROOT', self.root), patch.object(client.subprocess, 'run') as run:
            selected = client.resolver_source_paths()
            self.assertEqual([path.name for path in selected], ['GmsFixture.java', 'ResolvedGateSet.java'])
            self.assertEqual(set(client.client_source_paths()),
                             {self.root / name for name in [*names, 'publication-files.json']})
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
