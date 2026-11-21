"""No server is started: request handlers execute against in-memory streams and fake options."""
import importlib
import io
import json
import logging
import os
import sys
import types
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

class ManagedApiTest(unittest.TestCase):
    token = 'cph-unit-test-' * 4
    def load(self, enabled=True):
        env = {'BURP_DIAG_MANAGED': '1' if enabled else '0', 'BURP_DIAG_CPH_TOKEN': self.token}
        with patch.dict(os.environ, env):
            import CPH_Managed
            importlib.reload(CPH_Managed)
            import CPH_API_v0_2
            importlib.reload(CPH_API_v0_2)
        return CPH_Managed, CPH_API_v0_2

    def handler(self, api, path, authorization=None, body=None):
        handler = api.CphApiHandler.__new__(api.CphApiHandler)
        handler.path = path
        handler.headers = {}
        if authorization is not None:
            handler.headers['Authorization'] = authorization
        raw = json.dumps(body or {}).encode()
        handler.headers['Content-Length'] = str(len(raw))
        handler.rfile = io.BytesIO(raw)
        handler.reply = None
        handler._send_json = lambda code, value: setattr(handler, 'reply', (code, value))
        return handler

    def test_get_and_post_without_token_do_not_access_options(self):
        _, api = self.load()
        api.CphApiHandler.options_tab_getter = staticmethod(lambda: self.fail('Unauthorized options access'))
        for path, method in [('/cph/export', 'do_GET'), ('/cph/import', 'do_POST'), ('/cph/health', 'do_GET')]:
            handler = self.handler(api, path)
            getattr(handler, method)()
            self.assertEqual(403, handler.reply[0])

    def test_wrong_token_rejected(self):
        managed, api = self.load()
        self.assertFalse(managed.authorized('Bearer wrong'))
        handler = self.handler(api, '/cph/import', 'Bearer wrong')
        handler.do_POST()
        self.assertEqual(403, handler.reply[0])

    def test_authorized_export_keeps_config_and_reports_managed_instance(self):
        _, api = self.load()
        config = OrderedDict([('job:example:source', {'enabled': True}), ('job:example:dest', {'cached_selection': 'job:example:source'})])
        class Options:
            def prepare_to_save_all(self): return config
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        handler = self.handler(api, '/cph/export', 'Bearer ' + self.token)
        handler.do_GET()
        self.assertEqual((200, True), (handler.reply[0], handler.reply[1]['managed']))
        self.assertEqual(config, handler.reply[1]['config'])
        self.assertEqual('environment',handler.reply[1]['connection']['source'])
        self.assertNotIn(self.token,json.dumps(handler.reply[1]))

    def test_unauthorized_response_does_not_disclose_connection_paths(self):
        _,api=self.load()
        handler=self.handler(api,'/cph/export')
        handler.do_GET()
        self.assertEqual((403,{'success':False,'message':'CPH_AUTH_REQUIRED'}),handler.reply)

    def test_import_retains_keep_mode_and_source_before_destination(self):
        _, api = self.load()
        calls = []
        class Options:
            def load_config(self, config, replace): calls.append((list(config), replace))
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token,
                               OrderedDict([('job:a:source', {}), ('job:a:dest', {})]))
        handler.do_POST()
        self.assertEqual(200, handler.reply[0])
        self.assertEqual([(['job:a:source', 'job:a:dest'], False)], calls)

    def test_malformed_expression_in_later_tab_is_rejected_before_ui_mutation(self):
        _, api = self.load()
        calls = []
        class Options:
            def load_config(self, config, replace): calls.append((list(config), replace))
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        config = OrderedDict([
            ('job:a:source', {'static_expression': [True, 'source']}),
            ('job:a:second', {'static_expression': [True, 'second']}),
            ('job:a:third', {'static_expression': [True, 'third']}),
            ('job:a:fourth', {'static_expression': 'Cookie: PHPSESSID=sample\\r\\n'})])
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token, config)
        handler.do_POST()
        self.assertEqual(500, handler.reply[0])
        self.assertEqual('CPH_API_FAILED', handler.reply[1]['message'])
        self.assertEqual('CPH_FIELD_SHAPE_INVALID', handler.reply[1]['code'])
        self.assertEqual('job:a:fourth', handler.reply[1]['tabName'])
        self.assertEqual('static_expression', handler.reply[1]['fieldName'])
        self.assertEqual([], calls)

    def test_static_expression_real_newline_is_rejected_but_literal_escape_is_accepted(self):
        _, api = self.load()
        calls = []
        class Options:
            def load_config(self, config, replace): calls.append((config, replace))
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        name = 'job:a:source'
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token,
                               {name: {'static_expression': [True, 'value\r\n']}})
        handler.do_POST()
        self.assertEqual('CPH_SINGLE_LINE_CONTROL_CHARACTER', handler.reply[1]['code'])
        self.assertEqual([], calls)
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token,
                               {name: {'static_expression': [True, r'\r\n']}})
        handler.do_POST()
        self.assertEqual(200, handler.reply[0])
        self.assertEqual(1, len(calls))

    def atomic_fixture(self, fail_first=False, fail_rollback=False, native_tuple=False, unused_mode=None):
        _, api = self.load()
        before = OrderedDict([('job:old:source', {'enabled': False})])
        if unused_mode is not None:
            before['human-unused'] = {'enabled': True, 'dynamic_checkbox': unused_mode == 'single',
                'extract_choice_index': 0 if unused_mode == 'single' else 2, 'cached_selection': 'deleted-source'}
        desired = OrderedDict(before)
        desired['job:new:destination'] = {'enabled': True, 'static_expression': [True, r'\\r\\n']}
        current = OrderedDict((key, dict(value)) for key, value in before.items())
        tabs = []
        class Tab:
            def __init__(self, name):
                self.namepane_txtfield = types.SimpleNamespace(getText=lambda: name)
                self.emv_tab = name
        tabs.extend(Tab(name) for name in before)
        class MainPane:
            def setSelectedIndex(self, index):
                self.test_case.assertEqual(0, index)
            def remove(self, tab):
                tabs.remove(tab)
                current.pop(tab.namepane_txtfield.getText(), None)
        class MainTab:
            mainpane = MainPane()
            @staticmethod
            def get_config_tabs(): return list(tabs)
        MainTab.mainpane.test_case = self
        class EmvPane:
            def remove(self, value): pass
        class Options:
            emv_tab_pane = EmvPane()
            failed = False
            def prepare_to_save_all(self):
                result = OrderedDict((key, dict(value)) for key, value in current.items())
                if native_tuple and 'job:new:destination' in result:
                    result['job:new:destination']['static_expression'] = tuple(result['job:new:destination']['static_expression'])
                return result
            def load_config(self, config, replace):
                self.test_case.assertFalse(replace)
                if self.failed and fail_rollback:
                    raise ValueError('rollback-secret')
                for name, value in config.items():
                    if name not in current:
                        tabs.append(Tab(name))
                    current[name] = dict(value)
                    if fail_first and name == 'job:new:destination' and not self.failed:
                        self.failed = True
                        tabs[-1].namepane_txtfield = types.SimpleNamespace(getText=lambda: 'Unconfigured')
                        current['Unconfigured'] = current.pop(name)
                        raise ValueError('setter-secret')
                reordered = OrderedDict((name, current[name]) for name in config)
                current.clear();current.update(reordered)
        options = Options();options.test_case = self
        api.CphApiHandler.options_tab_getter = staticmethod(lambda: options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-atomic'))
        api.CphApiHandler.main_tab_getter = staticmethod(lambda: MainTab)
        return api, MainTab, before, desired, current, tabs

    def test_atomic_import_rolls_back_only_created_tab_after_setter_failure(self):
        api, main, before, desired, current, tabs = self.atomic_fixture(fail_first=True)
        payload = {'operationId': 'test:prepare-apply:reflection', 'expected': before, 'config': desired}
        handler = self.handler(api, '/cph/import-atomic', 'Bearer ' + self.token, payload)
        handler.do_POST()
        self.assertEqual(500, handler.reply[0])
        self.assertEqual('CPH_IMPORT_FAILED', handler.reply[1]['code'])
        self.assertNotIn('setter-secret', str(handler.reply))
        self.assertEqual(before, current)
        self.assertEqual(['job:old:source'], [tab.namepane_txtfield.getText() for tab in tabs])

    def test_atomic_import_applies_multiple_tabs_in_order_and_echoes_operation(self):
        api, main, before, desired, current, tabs = self.atomic_fixture(native_tuple=True)
        payload = {'operationId': 'test:prepare-apply:reflection', 'expected': before, 'config': desired}
        handler = self.handler(api, '/cph/import-atomic', 'Bearer ' + self.token, payload)
        handler.do_POST()
        self.assertEqual(200, handler.reply[0])
        self.assertEqual(payload['operationId'], handler.reply[1]['operationId'])
        self.assertEqual(desired, current)
        self.assertEqual(list(desired), [tab.namepane_txtfield.getText() for tab in tabs])

    def test_atomic_import_preserves_unused_static_and_single_cache_fields(self):
        for mode in ('static', 'single'):
            with self.subTest(mode=mode):
                api, main, before, desired, current, tabs = self.atomic_fixture(unused_mode=mode)
                api.atomic_import(api.CphApiHandler.options_tab_getter(), main, 'fixture:unused-cache', before, desired)
                self.assertEqual(desired, current)
                self.assertEqual(before['human-unused'], current['human-unused'])
                self.assertEqual(list(desired), [tab.namepane_txtfield.getText() for tab in tabs])

    def test_atomic_setter_failure_restores_unused_cache_baseline_without_masking_cause(self):
        for mode in ('static', 'single'):
            with self.subTest(mode=mode):
                api, main, before, desired, current, tabs = self.atomic_fixture(fail_first=True, unused_mode=mode)
                with self.assertRaises(api.CphAtomicError) as caught:
                    api.atomic_import(api.CphApiHandler.options_tab_getter(), main, 'fixture:unused-rollback', before, desired)
                self.assertEqual('CPH_IMPORT_FAILED', caught.exception.code)
                self.assertEqual(before, current)
                self.assertEqual(list(before), [tab.namepane_txtfield.getText() for tab in tabs])

    def test_unused_cache_preservation_does_not_bypass_whole_configuration_readback(self):
        api, main, before, desired, current, tabs = self.atomic_fixture(unused_mode='static')
        options = api.CphApiHandler.options_tab_getter()
        native_load = options.load_config
        damaged = []
        def import_with_once_only_field_loss(config, replace):
            native_load(config, replace)
            if not damaged:
                damaged.append(True);current['human-unused']['enabled'] = False
        options.load_config = import_with_once_only_field_loss
        with self.assertRaises(api.CphAtomicError) as caught:
            api.atomic_import(options, main, 'fixture:full-readback', before, desired)
        self.assertEqual('CPH_IMPORT_READBACK_MISMATCH', caught.exception.code)
        self.assertEqual(before, current)
        self.assertEqual(list(before), [tab.namepane_txtfield.getText() for tab in tabs])

    def test_atomic_comparison_ignores_object_field_order_but_keeps_tab_order(self):
        api, main, before, desired, current, tabs = self.atomic_fixture(unused_mode='static')
        options = api.CphApiHandler.options_tab_getter()
        native_prepare = options.prepare_to_save_all
        def fixed_native_field_order():
            return OrderedDict((name, OrderedDict(sorted(value.items()))) for name, value in native_prepare().items())
        options.prepare_to_save_all = fixed_native_field_order
        with self.assertRaises(api.CphAtomicError) as caught:
            api.atomic_import(options, main, 'fixture:wrong-tab-order', OrderedDict(reversed(list(before.items()))), desired)
        self.assertEqual('CPH_IMPORT_BASELINE_CHANGED', caught.exception.code)
        self.assertEqual(before, current)
        expected = OrderedDict((name, OrderedDict(reversed(list(value.items())))) for name, value in before.items())
        api.atomic_import(options, main, 'fixture:object-order', expected, desired)
        self.assertEqual(desired, current)
        self.assertFalse(api.same_native_config({'x': {'enabled': False}}, {'x': {'enabled': 0}}))
        self.assertFalse(api.same_native_config({'x': {'a': [1, 2]}}, {'x': {'a': [2, 1]}}))
        self.assertFalse(api.same_native_config({'x': {}}, {'x': {'cached_selection': None}}))

    def test_required_cache_preflight_keeps_precise_error_without_running_rollback_setters(self):
        _, api = self.load()
        before = OrderedDict([('human-cache', {'enabled': True, 'dynamic_checkbox': True,
            'extract_choice_index': 2, 'cached_selection': 'deleted-source'})])
        desired = OrderedDict(before);desired['job:new:static'] = {'enabled': True}
        calls = []
        marker = object()
        class Main:
            @staticmethod
            def get_config_tabs(): return [marker]
        class Options:
            def prepare_to_save_all(self): return before
            def load_config(self, config, replace): calls.append(config);raise AssertionError('must not mutate')
        with self.assertRaises(api.CphAtomicError) as caught:
            api.atomic_import(Options(), Main, 'fixture:required-cache', before, desired)
        error = api.failure_body(caught.exception)
        self.assertEqual('CPH_CACHE_REFERENCE_ORDER', error['code'])
        self.assertEqual('preflight', error['stage'])
        self.assertEqual('human-cache', error['tabName'])
        self.assertEqual('cached_selection', error['fieldName'])
        self.assertEqual([], calls)

    def test_atomic_import_rejects_changed_baseline_without_mutation(self):
        api, main, before, desired, current, tabs = self.atomic_fixture()
        payload = {'operationId': 'test:prepare-apply:reflection',
                   'expected': OrderedDict([('job:old:source', {'enabled': True})]), 'config': desired}
        handler = self.handler(api, '/cph/import-atomic', 'Bearer ' + self.token, payload)
        handler.do_POST()
        self.assertEqual('CPH_IMPORT_BASELINE_CHANGED', handler.reply[1]['code'])
        self.assertEqual(before, current)
        self.assertEqual(1, len(tabs))

    def test_atomic_import_rejects_invalid_operation_id_without_echoing_it(self):
        api, main, before, desired, current, tabs = self.atomic_fixture()
        payload = {'operationId': 'secret\nvalue', 'expected': before, 'config': desired}
        handler = self.handler(api, '/cph/import-atomic', 'Bearer ' + self.token, payload)
        handler.do_POST()
        self.assertEqual('CPH_OPERATION_ID_INVALID', handler.reply[1]['code'])
        self.assertNotIn('operationId', handler.reply[1])
        self.assertNotIn('secret', str(handler.reply))
        self.assertEqual(before, current)

    def test_atomic_import_reports_unknown_when_rollback_fails(self):
        api, main, before, desired, current, tabs = self.atomic_fixture(fail_first=True, fail_rollback=True)
        payload = {'operationId': 'test:prepare-apply:reflection', 'expected': before, 'config': desired}
        handler = self.handler(api, '/cph/import-atomic', 'Bearer ' + self.token, payload)
        handler.do_POST()
        self.assertEqual('CPH_ROLLBACK_OUTCOME_UNKNOWN', handler.reply[1]['code'])
        self.assertNotIn('rollback-secret', str(handler.reply))

    def test_prune_removes_only_disabled_named_tabs(self):
        _, api = self.load()
        config = OrderedDict([('job:old:one', {'enabled': False}),
                              ('job:new:two', {'enabled': False}), ('options', {'enabled': True})])
        removed = []
        class Tab:
            def __init__(self, name):
                self.namepane_txtfield = types.SimpleNamespace(getText=lambda: name)
                self.emv_tab = name
        tabs = [Tab('job:old:one'), Tab('job:new:two')]
        class MainPane:
            def remove(self, tab):
                removed.append(tab.namepane_txtfield.getText())
                tabs.remove(tab)
        class MainTab:
            mainpane = MainPane()
            @staticmethod
            def get_config_tabs(): return tabs
        class EmvPane:
            def remove(self, value): pass
        class Options:
            emv_tab_pane = EmvPane()
            def prepare_to_save_all(self):
                return OrderedDict((key, value) for key, value in config.items() if key not in removed)
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        api.CphApiHandler.main_tab_getter = staticmethod(lambda: MainTab)
        handler = self.handler(api, '/cph/prune', 'Bearer ' + self.token,
                               {'names': ['job:old:one'], 'expected': config})
        handler.do_POST()
        self.assertEqual(200, handler.reply[0])
        self.assertEqual(1, handler.reply[1]['removedCount'])
        self.assertEqual(['job:old:one'], removed)
        self.assertEqual(['job:new:two'], [tab.namepane_txtfield.getText() for tab in tabs])

    def test_prune_rejects_changed_baseline_and_enabled_tabs_before_mutation(self):
        _, api = self.load()
        config = OrderedDict([('job:old:one', {'enabled': False}), ('options', {'enabled': True})])
        class Options:
            def prepare_to_save_all(self): return config
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        api.CphApiHandler.main_tab_getter = staticmethod(lambda: None)
        for expected, names in [({'job:old:one': {'enabled': True}, 'options': {'enabled': True}}, ['job:old:one']),
                                (config, ['options'])]:
            handler = self.handler(api, '/cph/prune', 'Bearer ' + self.token,
                                   {'names': names, 'expected': expected})
            handler.do_POST()
            self.assertEqual(500, handler.reply[0])

    def test_prune_requires_managed_mode_and_token(self):
        _, api = self.load()
        handler = self.handler(api, '/cph/prune')
        handler.do_POST()
        self.assertEqual(403, handler.reply[0])
        _, api = self.load(False)
        handler = self.handler(api, '/cph/prune')
        handler.do_POST()
        self.assertEqual(403, handler.reply[0])

    def test_legacy_mode_preserves_unauthenticated_operation(self):
        managed, api = self.load(False)
        self.assertTrue(managed.authorized(None))
        handler = self.handler(api, '/cph/health')
        handler.do_GET()
        self.assertEqual(200, handler.reply[0])

    def test_internal_failure_is_not_exposed_as_success_or_secret_text(self):
        _, api = self.load()
        class Options:
            def load_config(self, config, replace): raise ValueError('secret-token-in-error')
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token)
        handler.do_POST()
        self.assertEqual(500, handler.reply[0])
        self.assertFalse(handler.reply[1]['success'])
        self.assertNotIn('secret-token', str(handler.reply))

    def test_log_filter_suppresses_values_and_exception_details(self):
        managed, _ = self.load()
        logger = logging.getLogger('managed-filter-test')
        managed.install_log_filter(logger)
        record = logging.LogRecord(logger.name, logging.WARNING, __file__, 1, 'token=%s', ('secret',), None)
        self.assertTrue(logger.filter(record))
        self.assertNotIn('secret', record.getMessage())
        self.assertEqual((), record.args)

    def test_import_body_size_limit_precedes_native_mutation(self):
        _, api = self.load()
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token)
        handler.headers['Content-Length'] = str(17 * 1024 * 1024)
        handler.do_POST()
        self.assertEqual(413, handler.reply[0])

    def test_missing_managed_secret_fails_closed_at_startup(self):
        import CPH_Managed
        with patch.dict(os.environ, {'BURP_DIAG_MANAGED': '1', 'BURP_DIAG_CPH_TOKEN': ''}):
            with self.assertRaises(ValueError): importlib.reload(CPH_Managed)
        self.load()

    def test_normalization_keeps_an_ordered_mapping_for_the_jython_wire_encoder(self):
        _, api = self.load()
        handler = self.handler(api, '/cph/export', 'Bearer ' + self.token)
        config = OrderedDict([('job:demo:source', {'enabled': True}), ('job:demo:destination', {'cached_selection': 'job:demo:source'})])
        normalized = handler._normalize_for_json(config)
        self.assertIsInstance(normalized, OrderedDict)
        self.assertEqual(list(config), list(json.loads(json.dumps(normalized), object_pairs_hook=OrderedDict)))

    def cached_import(self, enabled=True, lost=None, repair=True, tab_enabled=True, dynamic=True, reference='source', existing=False):
        _, api = self.load(enabled)
        config = OrderedDict([('source', {'enabled': True}), ('dest', {
            'enabled': tab_enabled, 'dynamic_checkbox': dynamic, 'extract_choice_index': 2, 'cached_selection': reference})])
        calls = []
        current = OrderedDict((name, dict(tab)) for name, tab in config.items()) if existing else OrderedDict()
        class Options:
            def load_config(self, value, replace):
                calls.append((list(value), replace))
                current.update((name, dict(tab)) for name, tab in value.items())
                if len(value) > 1 or not repair:
                    current['dest']['cached_selection'] = lost
            def prepare_to_save_all(self): return current
        api.CphApiHandler.options_tab_getter = staticmethod(Options)
        api.CphApiHandler.logger_getter = staticmethod(lambda: logging.getLogger('test-cph-api'))
        handler = self.handler(api, '/cph/import', 'Bearer ' + self.token, config)
        handler.do_POST()
        return handler, calls, current

    def test_missing_cached_reference_is_restored_without_reordering_again(self):
        handler, calls, current = self.cached_import()
        self.assertEqual(200, handler.reply[0])
        self.assertEqual([(['source', 'dest'], False), (['dest'], False)], calls)
        self.assertEqual('source', current['dest']['cached_selection'])
        self.assertEqual(['source', 'dest'], list(current))

    def test_disabled_cached_reference_is_preserved_for_later_reenable(self):
        handler, calls, current = self.cached_import(tab_enabled=False)
        self.assertEqual(200, handler.reply[0])
        self.assertEqual('source', current['dest']['cached_selection'])
        self.assertFalse(current['dest']['enabled'])
        self.assertEqual([(['source', 'dest'], False), (['dest'], False)], calls)

    def test_disabled_conflicting_reference_is_not_silently_overwritten(self):
        handler, calls, _ = self.cached_import(lost='other-source', tab_enabled=False)
        self.assertEqual(500, handler.reply[0])
        self.assertEqual(1, len(calls))

    def test_configured_reference_survives_a_temporary_static_mode(self):
        handler, calls, current = self.cached_import(tab_enabled=False, dynamic=False)
        self.assertEqual(200, handler.reply[0])
        self.assertEqual('source', current['dest']['cached_selection'])
        self.assertFalse(current['dest']['dynamic_checkbox'])
        self.assertEqual(2, len(calls))

    def test_unused_cache_reference_matches_readback_for_existing_changed_and_new_handlers(self):
        _, api = self.load()
        for mode in ('static', 'single'):
            for existing, changed in ((True, False), (True, True), (False, False)):
                with self.subTest(mode=mode, existing=existing, changed=changed):
                    tab = {'enabled': True, 'dynamic_checkbox': mode == 'single',
                        'extract_choice_index': 0 if mode == 'single' else 2, 'cached_selection': 'deleted-source'}
                    current = OrderedDict([('human-unused', dict(tab))]) if existing else OrderedDict()
                    desired = OrderedDict([('human-unused', dict(tab))])
                    if changed: desired['human-unused']['static_expression'] = [True, 'approved change']
                    desired['job:new:static'] = {'enabled': True}
                    class Options:
                        def prepare_to_save_all(self): return current
                        def load_config(self, config, replace): current.update((name, dict(value)) for name, value in config.items())
                    api.load_config_keep(Options(), desired)
                    self.assertEqual(desired, current)

    def test_unused_cache_loss_or_conflict_is_not_silently_accepted(self):
        _, api = self.load()
        for mode in ('static', 'single'):
            for observed in (None, 'different-source'):
                with self.subTest(mode=mode, observed=observed):
                    tab = {'enabled': True, 'dynamic_checkbox': mode == 'single',
                        'extract_choice_index': 0 if mode == 'single' else 2, 'cached_selection': 'deleted-source'}
                    current = OrderedDict([('human-unused', dict(tab))])
                    desired = OrderedDict(current);desired['job:new:static'] = {'enabled': True}
                    class Options:
                        def prepare_to_save_all(self): return current
                        def load_config(self, config, replace):
                            current.update((name, dict(value)) for name, value in config.items())
                            current['human-unused']['cached_selection'] = observed
                    with self.assertRaises(api.CphAtomicError) as caught:
                        api.load_config_keep(Options(), desired)
                    self.assertEqual('CPH_IMPORT_READBACK_MISMATCH', caught.exception.code)
                    self.assertEqual('human-unused', api.failure_body(caught.exception)['tabName'])

    def test_actual_cache_null_source_and_native_order_drift_remain_refused(self):
        _, api = self.load()
        calls = []
        invalid = OrderedDict([('dest', {'enabled': True, 'dynamic_checkbox': True,
            'extract_choice_index': 2, 'cached_selection': None})])
        class Options:
            current = OrderedDict()
            def prepare_to_save_all(self): return self.current
            def load_config(self, config, replace):
                calls.append(config);self.current = OrderedDict(reversed(list(config.items())))
        options = Options()
        with self.assertRaises(api.CphAtomicError) as caught:
            api.load_config_keep(options, invalid)
        self.assertEqual('CPH_CACHE_REFERENCE_REQUIRED', caught.exception.code)
        self.assertEqual([], calls)
        valid = OrderedDict([('source', {'enabled': False}), ('dest', {'enabled': True,
            'dynamic_checkbox': True, 'extract_choice_index': 2, 'cached_selection': 'source'})])
        with self.assertRaises(api.CphAtomicError) as caught:
            api.load_config_keep(options, valid)
        self.assertEqual('CPH_CACHE_REFERENCE_ORDER', caught.exception.code)
        self.assertEqual('readback', caught.exception.stage)
        self.assertEqual(1, len(calls))

    def test_disabled_unconfigured_cache_does_not_require_a_reference(self):
        handler, calls, current = self.cached_import(tab_enabled=False, reference=None, existing=True)
        self.assertEqual(200, handler.reply[0])
        self.assertIsNone(current['dest']['cached_selection'])
        self.assertEqual(1, len(calls))

    def test_new_disabled_cached_definition_requires_a_source_before_mutation(self):
        handler, calls, _ = self.cached_import(tab_enabled=False, reference=None)
        self.assertEqual(500, handler.reply[0])
        self.assertEqual([], calls)

    def test_unchanged_inactive_missing_reference_is_preserved_with_unrelated_import(self):
        _, api = self.load()
        for reference in (None, '', 'deleted-source'):
            with self.subTest(reference=reference):
                current = OrderedDict([('human-disabled', {'enabled': False, 'dynamic_checkbox': True,
                    'extract_choice_index': 2, 'cached_selection': reference})])
                desired = OrderedDict(current)
                desired['job:new:static'] = {'enabled': True, 'static_expression': [True, 'fixture']}
                calls = []
                class Options:
                    def prepare_to_save_all(self): return current
                    def load_config(self, config, replace):
                        calls.append(list(config))
                        current.update((name, dict(tab)) for name, tab in config.items())
                api.load_config_keep(Options(), desired)
                self.assertEqual(desired, current)
                self.assertEqual([list(desired)], calls)

    def test_active_dependency_cannot_use_an_inactive_source_with_missing_reference(self):
        _, api = self.load()
        current = OrderedDict([('source', {'enabled': False, 'dynamic_checkbox': True,
            'extract_choice_index': 2, 'cached_selection': 'deleted-source'})])
        desired = OrderedDict(current)
        desired['dest'] = {'enabled': True, 'dynamic_checkbox': True,
            'extract_choice_index': 2, 'cached_selection': 'source'}
        class Options:
            def prepare_to_save_all(self): return current
            def load_config(self, config, replace): self.fail('must not mutate')
        with self.assertRaisesRegex(ValueError, 'CPH_CACHE_REFERENCE_ORDER'):
            api.load_config_keep(Options(), desired)

    def test_atomic_unchanged_candidate_never_imports_incomplete_inactive_definitions(self):
        _, api = self.load()
        current = OrderedDict([('human-disabled', {'enabled': False, 'dynamic_checkbox': True,
            'extract_choice_index': 2, 'cached_selection': 'deleted-source'})])
        class Options:
            def prepare_to_save_all(self): return current
            def load_config(self, config, replace): raise AssertionError('unchanged candidate imported')
        api.atomic_import(Options(), None, 'fixture:no-op', current, current)

    def test_conflicting_cached_reference_is_not_silently_overwritten(self):
        handler, calls, _ = self.cached_import(lost='other-source')
        self.assertEqual(500, handler.reply[0])
        self.assertEqual(1, len(calls))

    def test_unsuccessful_cached_reference_repair_is_not_reported_as_success(self):
        handler, calls, _ = self.cached_import(repair=False)
        self.assertEqual(500, handler.reply[0])
        self.assertEqual(2, len(calls))

    def test_legacy_cached_import_keeps_the_existing_single_import_behavior(self):
        handler, calls, _ = self.cached_import(enabled=False)
        self.assertEqual(200, handler.reply[0])
        self.assertEqual(1, len(calls))

if __name__ == '__main__':
    unittest.main()
