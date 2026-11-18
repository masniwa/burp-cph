"""No server is started: request handlers execute against in-memory streams and fake options."""
import importlib
import io
import json
import logging
import os
import sys
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

    def cached_import(self, enabled=True, lost=None, repair=True, tab_enabled=True, dynamic=True, reference='source'):
        _, api = self.load(enabled)
        config = OrderedDict([('source', {'enabled': True}), ('dest', {
            'enabled': tab_enabled, 'dynamic_checkbox': dynamic, 'extract_choice_index': 2, 'cached_selection': reference})])
        calls = []
        current = OrderedDict()
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

    def test_disabled_unconfigured_cache_does_not_require_a_reference(self):
        handler, calls, current = self.cached_import(tab_enabled=False, reference=None)
        self.assertEqual(200, handler.reply[0])
        self.assertIsNone(current['dest']['cached_selection'])
        self.assertEqual(1, len(calls))

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
