import json
import sys
import tempfile
import unittest
import os
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with patch.dict(os.environ, {'BURP_DIAG_MANAGED':'1','BURP_DIAG_CPH_TOKEN':'test-import-only-'*4}):
    import CPH_Managed

class RuntimeProfileTest(unittest.TestCase):
    def temporary(self):
        directory=Path(__file__).resolve().parents[2]/'temp'
        directory.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(dir=str(directory))
    def test_file_profile_enables_authentication_without_launch_environment(self):
        with self.temporary() as d:
            p=Path(d)
            (p/'settings.json').write_text('{"schemaVersion":1}',encoding='utf-8')
            (p/'operator-secrets.json').write_text(json.dumps({'worker':'w'*48,'cph':'c'*48}),encoding='utf-8')
            self.assertEqual((True,'c'*48),CPH_Managed.load_configuration({},d))
            self.assertEqual((False,''),CPH_Managed.load_configuration({'BURP_DIAG_MANAGED':'0'},d))

    def test_partial_or_invalid_profiles_fail_closed(self):
        with self.temporary() as d:
            p=Path(d);(p/'settings.json').write_text('{}',encoding='utf-8')
            with self.assertRaises(ValueError):CPH_Managed.load_configuration({},d)
            (p/'operator-secrets.json').write_text('{"cph":"short"}',encoding='utf-8')
            with self.assertRaises(ValueError):CPH_Managed.load_configuration({},d)

    def test_standalone_legacy_without_profile_stays_legacy(self):
        with self.temporary() as d:
            self.assertEqual((False,''),CPH_Managed.load_configuration({},d))

    def test_explicit_stale_reference_fails_closed_without_creating_a_runtime(self):
        with self.temporary() as d:
            p=Path(d)
            (p/'cph-connection.json').write_text('{"runtimeDirectory":"../missing-runtime"}',encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'CPH_RUNTIME_PROFILE_MISSING'):
                CPH_Managed.load_configuration({},d)
            self.assertFalse((p.parent/'missing-runtime').exists())

    def test_relative_reference_survives_moving_the_whole_installation(self):
        with self.temporary() as d:
            base=Path(d)/'installation 日本語'
            cph=base/'custom-cph'/'runtime'; cph.mkdir(parents=True)
            mcp=base/'mcp-server-latest'/'runtime'; mcp.mkdir(parents=True)
            (mcp/'settings.json').write_text('{"schemaVersion":1}',encoding='utf-8')
            (mcp/'operator-secrets.json').write_text(json.dumps({'worker':'w'*48,'cph':'c'*48}),encoding='utf-8')
            (cph/'cph-connection.json').write_text('{"runtimeDirectory":"../../mcp-server-latest/runtime"}',encoding='utf-8')
            self.assertEqual((True,'c'*48),CPH_Managed.load_configuration({},str(cph)))
            moved=Path(d)/'moved installation'; base.rename(moved)
            enabled,token,metadata=CPH_Managed.configuration({},str(moved/'custom-cph'/'runtime'))
            self.assertTrue(enabled); self.assertEqual('c'*48,token)
            self.assertEqual(str(moved/'mcp-server-latest'/'runtime'),metadata['runtimeDirectory'])
            self.assertNotIn(token,json.dumps(metadata))

    def test_renaming_only_mcp_requires_repair_and_never_selects_a_sibling(self):
        with self.temporary() as d:
            p=Path(d); cph=p/'cph'; cph.mkdir(); target=p/'mcp'; target.mkdir()
            (target/'settings.json').write_text('{}',encoding='utf-8')
            (target/'operator-secrets.json').write_text(json.dumps({'worker':'w'*48,'cph':'c'*48}),encoding='utf-8')
            pointer=cph/'cph-connection.json'; pointer.write_text('{"runtimeDirectory":"../mcp"}',encoding='utf-8')
            target.rename(p/'mcp-latest')
            with self.assertRaisesRegex(ValueError,'CPH_RUNTIME_PROFILE_MISSING'):
                CPH_Managed.load_configuration({},str(cph))
            pointer.write_text('{"runtimeDirectory":"../mcp-latest"}',encoding='utf-8')
            self.assertEqual((True,'c'*48),CPH_Managed.load_configuration({},str(cph)))

    def test_empty_and_non_string_references_are_not_accepted(self):
        with self.temporary() as d:
            p=Path(d)
            for value in ['', ' ', None, 42, []]:
                (p/'cph-connection.json').write_text(json.dumps({'runtimeDirectory':value}),encoding='utf-8')
                with self.assertRaisesRegex(ValueError,'CPH_RUNTIME_PROFILE_INVALID'):
                    CPH_Managed.load_configuration({},d)

if __name__=='__main__':unittest.main()
