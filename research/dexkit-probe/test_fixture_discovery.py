#!/usr/bin/env python3
"""Run real host DexKit candidate queries on generated synthetic DEX fixtures.

These checks compare actual query output with independently supplied fixture
descriptors. Namespace graph evidence establishes reachability only; it cannot
prove operand flow, a receiver's identity, or semantic permission to hook.
Neither GMS classes nor fixture business methods are executed by this test.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from project_paths import BUILD_ROOT, ROOT  # noqa: E402
from run_probe import TOOLS, verified_tools  # noqa: E402


SOURCE = Path(__file__).resolve().parent
CASES = json.loads((SOURCE / 'fixtures/cases.json').read_text())
FIXTURES = BUILD_ROOT / 'dexkit-probe/fixtures'
CLASSES = BUILD_ROOT / 'dexkit-probe/classes'
NAMESPACE = 'com.google.android.gms.nearby'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FixtureDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which('java')
        cls.jars, cls.native = verified_tools()
        required = [CLASSES / 'GmsDexProbe.class', cls.native, *cls.jars]
        if not cls.java or not cls.jars or any(not path.is_file() for path in required):
            raise RuntimeError('Compile the host GmsDexProbe and provide local DexKit dependencies first.')
        source_sha256 = sha(SOURCE / 'GmsDexProbe.java')
        stamp = CLASSES / 'source.sha256'
        if not stamp.is_file() or stamp.read_text().strip() != source_sha256:
            raise RuntimeError('Compile this exact GmsDexProbe source first with run_probe.py --compile.')
        cls.classpath = os.pathsep.join(str(path.resolve()) for path in [CLASSES, *cls.jars])
        cls.provenance = {
            'probe_source_sha256': source_sha256,
            'probe_class_sha256': sha(CLASSES / 'GmsDexProbe.class'),
            'tool_manifest_sha256': sha(TOOLS / 'tool-provenance.json'),
            'native_sha256': sha(cls.native),
            'jars_sha256': {path.name: sha(path) for path in cls.jars},
        }

    def run_fixture(self, case):
        directory = FIXTURES / case['id']
        # A failed rerun must not leave an earlier passing verdict/report live.
        for name in ('probe.json', 'probe-check.json'):
            (directory / name).unlink(missing_ok=True)
        metadata_path = directory / 'metadata.json'
        self.assertTrue(metadata_path.is_file(), 'Run fixtures.py before the discovery tests.')
        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata['fixture'], case, 'Fixture metadata must match current source design.')
        self.assertFalse(metadata['semantic_verification_performed'])
        container = directory / 'dex.zip'
        self.assertEqual(sha(container), metadata['zip_sha256'], 'Query the generated, unchanged container.')
        command = [self.java, '--enable-native-access=ALL-UNNAMED', '-cp', self.classpath,
                   'GmsDexProbe', str(self.native.resolve()), str(container.resolve())]
        # Only the DEX container is sent to the resolver, never expected answers.
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=45)
        (directory / 'probe.stdout.log').write_text(result.stdout)
        (directory / 'probe.stderr.log').write_text(result.stderr)
        (directory / 'probe-command.json').write_text(json.dumps({
            'argv': command, 'returncode': result.returncode, 'fixture_sha256': sha(container),
            **self.provenance,
        }, indent=2) + '\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        (directory / 'probe.json').write_text(json.dumps(report, indent=2) + '\n')
        self.assertTrue(report['report_only'])
        self.assertEqual(report['dex_count'], 1)
        self.assertTrue(any('do not prove' in line for line in report['limitations']))
        keys = {key['key']: key for key in report['keys']}
        self.assertEqual(set(keys), {'45704091', '45830365'})
        primary = keys['45704091']
        expected_count = 2 if 'duplicate_namespace' in case else 1
        self.assertEqual(primary['literal_match_count'], expected_count)
        self.assertEqual(len(primary['matches']), expected_count)
        self.assertEqual(metadata['raw_primary_declaration_count'], expected_count)
        literal_matches = {match['literal_method']['descriptor']: match for match in primary['matches']}
        declarations = metadata['primary_declarations']
        self.assertEqual(set(literal_matches), {item['factory'] for item in declarations})
        expects_supplier = case['expression'] not in ('false', 'true')
        self.assertEqual(metadata['supplier_directly_references_primary'], expects_supplier)
        namespace_hits = 0
        supplier_descriptors = set()

        for declaration in declarations:
            match = literal_matches[declaration['factory']]
            self.assertIn('45704091', match['literal_method']['strings'])
            self.assertNotIn(NAMESPACE, match['literal_method']['strings'],
                             'The namespace must not be colocated with the key as a shortcut.')
            # This checks the reachable <clinit> string, not its constructor
            # argument position or the identity of the builder receiving it.
            graph = match['namespace_graph_evidence']
            target_namespace = declaration['namespace'] == NAMESPACE
            self.assertEqual(bool(graph), target_namespace)
            if target_namespace:
                namespace_hits += 1
                owner = declaration['factory'].split('->', 1)[0]
                self.assertIn(owner + '-><clinit>()V', {method['descriptor'] for method in graph})
            self.assertEqual(len(match['getters']), 1)
            getter = match['getters'][0]
            self.assertEqual(getter['method']['descriptor'], declaration['getter'])
            self.assertIn(declaration['factory'], getter['method']['invokes'])
            self.assertIn(declaration['getter'], getter['contracts'])
            self.assertIn(metadata['interface_getter'], getter['contracts'])
            suppliers = getter['supplier_candidates']
            self.assertEqual({supplier['descriptor'] for supplier in suppliers},
                             {metadata['supplier']} if expects_supplier else set())
            self.assertEqual(metadata['supplier'] in getter['callers'], expects_supplier)
            for supplier in suppliers:
                self.assertIn(metadata['interface_getter'], supplier['invokes'])
                self.assertEqual(supplier['returns'], 'java.lang.Object')
                self.assertEqual(supplier['parameters'], [])
                supplier_descriptors.add(supplier['descriptor'])

        expected_namespace_hits = 1 + (case.get('duplicate_namespace') == NAMESPACE)
        self.assertEqual(namespace_hits, expected_namespace_hits)
        self.assertEqual(metadata['target_namespace_declaration_count'], expected_namespace_hits)
        secondary = keys['45830365']
        self.assertEqual(secondary['literal_match_count'], expected_count)
        secondary_suppliers = {supplier['descriptor'] for match in secondary['matches']
                               for getter in match['getters'] for supplier in getter['supplier_candidates']}
        self.assertEqual(secondary_suppliers,
                         {metadata['supplier']} if case['expression'] in ('A || B', 'A && B') else set())
        # AND, NOT, side-effect and discarded-read samples intentionally remain
        # candidate hits. Reporting them as rejected hooks would overstate this
        # call-graph query's capability; a semantic verifier is a separate stage.
        summary = {
            'fixture': case['id'], 'candidate_recall_checks_passed': True,
            'literal_match_count': primary['literal_match_count'],
            'namespace_graph_match_count': namespace_hits,
            'primary_supplier_candidates': sorted(supplier_descriptors),
            'source_shape': case['semantic_family'],
            'source_design_positive_shape': case['positive_shape'],
            'semantic_verification_performed': False,
            'namespace_graph_evidence_proves_dataflow': False,
            'approved_for_hooking': False,
        }
        (directory / 'probe-check.json').write_text(json.dumps(summary, indent=2) + '\n')


def make_case_test(case):
    def run(self):
        self.run_fixture(case)
    run.__doc__ = 'Actual DexKit candidate discovery: ' + case['semantic_family']
    return run


for fixture_case in CASES:
    setattr(FixtureDiscoveryTests, 'test_' + fixture_case['id'], make_case_test(fixture_case))


if __name__ == '__main__':
    unittest.main(verbosity=2)
