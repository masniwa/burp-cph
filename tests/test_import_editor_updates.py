"""Production import setter tests for the observed repeated-editor rendering cost."""
from pathlib import Path
from types import SimpleNamespace
import textwrap
import unittest


class ImportEditorUpdateTest(unittest.TestCase):
    def fixture(self, managed=True):
        source = (Path(__file__).resolve().parents[1] / 'CustomParamHandler_marged_api_v0.2.py').read_text(encoding='utf-8')
        method = textwrap.dedent(source[source.index('    def set_tab_values('):source.index('    def actionPerformed(', source.index('    def set_tab_values('))])
        values = dict(single_request='GET / HTTP/1.1\r\n\r\n', single_response='HTTP/1.1 200 OK\r\n\r\nexample', enabled=False, cached_selection='source')
        counts = dict.fromkeys(values, 0)
        warnings = []
        def setter(name, value):
            counts[name] += 1
            values[name] = value
        mechanisms = [SimpleNamespace(name=name, getter=lambda name=name: values[name], setter=lambda value, name=name: setter(name, value)) for name in values]
        pane = SimpleNamespace(setVisible=lambda value: None)
        tab = SimpleNamespace(config_mechanisms=mechanisms, param_handl_forwarder_socket_pane=pane, param_handl_dynamic_pane=pane)
        class Options: pass
        main = SimpleNamespace(logger=SimpleNamespace(warning=warnings.append), set_tab_name=lambda tab, name: None)
        namespace = dict(MainTab=main, OptionsTab=Options, managed=managed, JavaException=Exception, basestring=str, unicode=str)
        exec(compile(method, '<production native import setters>', 'exec'), namespace)
        return namespace['set_tab_values'], tab, values, counts, warnings

    def test_managed_identical_samples_do_not_render_again(self):
        apply, tab, values, counts, _ = self.fixture()
        apply(None, dict(values), tab, 'existing')
        self.assertEqual(0, counts['single_request'])
        self.assertEqual(0, counts['single_response'])
        self.assertEqual(1, counts['enabled'])
        self.assertEqual(1, counts['cached_selection'])

    def test_changed_request_is_applied_and_unchanged_response_is_preserved(self):
        apply, tab, values, counts, _ = self.fixture()
        desired = dict(values, single_request='GET /new HTTP/1.1\r\n\r\n')
        apply(None, desired, tab)
        self.assertEqual(desired, values)
        self.assertEqual(1, counts['single_request'])
        self.assertEqual(0, counts['single_response'])

    def test_changed_binary_response_is_applied_exactly_once(self):
        apply, tab, values, counts, _ = self.fixture()
        desired = dict(values, single_response='HTTP/1.1 200 OK\r\n\r\n' + bytes(range(256)).decode('latin1'))
        apply(None, desired, tab)
        apply(None, desired, tab)
        self.assertEqual(desired, values)
        self.assertEqual(1, counts['single_response'])

    def test_blank_replacement_is_a_real_update(self):
        apply, tab, values, counts, _ = self.fixture()
        apply(None, dict(values, single_request='', single_response=''), tab)
        self.assertEqual('', values['single_request'])
        self.assertEqual('', values['single_response'])
        self.assertEqual(1, counts['single_request'])
        self.assertEqual(1, counts['single_response'])

    def test_nontext_value_is_forwarded_to_the_existing_setter(self):
        apply, tab, values, counts, _ = self.fixture()
        apply(None, dict(values, single_response=None), tab)
        self.assertEqual(1, counts['single_response'])
        self.assertIsNone(values['single_response'])

    def test_missing_editor_value_is_not_equal_to_the_literal_none_text(self):
        apply, tab, values, counts, _ = self.fixture()
        values['single_response'] = None
        apply(None, dict(values, single_response='None'), tab)
        self.assertEqual(1, counts['single_response'])
        self.assertEqual('None', values['single_response'])

    def test_legacy_profile_keeps_setter_invocations(self):
        apply, tab, values, counts, _ = self.fixture(False)
        apply(None, dict(values), tab)
        self.assertTrue(all(value == 1 for value in counts.values()))

    def test_missing_fields_keep_warning_and_existing_values(self):
        apply, tab, values, counts, warnings = self.fixture()
        previous = dict(values)
        apply(None, dict(enabled=True), tab)
        self.assertEqual(previous['single_request'], values['single_request'])
        self.assertEqual(previous['single_response'], values['single_response'])
        self.assertTrue(values['enabled'])
        self.assertEqual(0, counts['cached_selection'])
        self.assertEqual(1, len(warnings))


if __name__ == '__main__': unittest.main()
