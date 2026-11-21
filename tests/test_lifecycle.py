"""Production lifecycle regressions using fake servers/callbacks; no sockets or UI."""
from pathlib import Path
from types import SimpleNamespace
import re
import textwrap
import unittest


SOURCE_PATH = Path(__file__).resolve().parents[1] / 'CustomParamHandler_marged_api_v0.2.py'


def production_method(source, name, after=''):
    begin = source.index('    def ' + name + '(', source.index(after) if after else 0)
    remaining = source[begin:]
    end = re.search(r'^(?:    @|    def |class )', remaining.split('\n', 1)[1], re.M)
    first_line_length = remaining.index('\n') + 1
    return textwrap.dedent(remaining[:first_line_length + end.start()] if end else remaining)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE_PATH.read_text(encoding='utf-8-sig')
        self.namespace = {}
        for name, after in [('actionPerformed', 'class OptionsTab('), ('extensionUnloaded', '')]:
            exec(compile(production_method(self.source, name, after), str(SOURCE_PATH) + ':' + name, 'exec'), self.namespace)
        self.trace = []
        self.api = self.server('api')
        self.demo = self.server('demo')
        self.api_thread, self.demo_thread = object(), object()
        self.options = SimpleNamespace(httpd=self.demo, httpd_thread=self.demo_thread,
            api_httpd=self.api, api_httpd_thread=self.api_thread,
            chkbox_demo=SimpleNamespace(setText=lambda value: self.trace.append(('demo-text', value))),
            emv_tab_pane=SimpleNamespace(getTabCount=lambda: 0),
            emv=SimpleNamespace(dispose=lambda: self.trace.append('viewer.dispose')),
            DEMO_INACTIVE='Run the built-in httpd for interactive demos',
            DEMO_ACTIVE='Running built-in httpd on {}:{}')
        for name in ['BTN_QUICKLOAD', 'BTN_IMPORTCONFIG', 'BTN_QUICKSAVE', 'BTN_DOCS', 'BTN_EMV', 'BTN_EXPORTCONFIG']:
            setattr(self.options, name, name)
        self.extender = SimpleNamespace(maintab=SimpleNamespace(options_tab=self.options,
            mainpane=SimpleNamespace(getTabCount=lambda: 0)))

    def server(self, name):
        return SimpleNamespace(server_address=('localhost', 9001),
            shutdown=lambda: self.trace.append(name + '.shutdown'),
            server_close=lambda: self.trace.append(name + '.server_close'))

    def stop_demo(self):
        command = self.options.DEMO_ACTIVE.format(*self.demo.server_address)
        event = SimpleNamespace(getActionCommand=lambda: command)
        self.namespace['actionPerformed'](self.options, event)

    def unload(self):
        self.namespace['extensionUnloaded'](self.extender)

    def test_stopping_demo_preserves_live_api_and_clears_only_demo_handles(self):
        self.stop_demo()
        self.assertIsNone(self.options.httpd)
        self.assertIsNone(self.options.httpd_thread)
        self.assertIs(self.api, self.options.api_httpd)
        self.assertIs(self.api_thread, self.options.api_httpd_thread)
        self.assertEqual(['demo.shutdown', 'demo.server_close', ('demo-text', self.options.DEMO_INACTIVE)], self.trace)

    def test_demo_stop_followed_by_unload_closes_api(self):
        self.stop_demo()
        self.unload()
        self.assertEqual(['demo.shutdown', 'demo.server_close', ('demo-text', self.options.DEMO_INACTIVE),
            'api.shutdown', 'api.server_close', 'viewer.dispose'], self.trace)
        self.assertIsNone(self.options.api_httpd)
        self.assertIsNone(self.options.api_httpd_thread)

    def test_unload_closes_both_servers_when_demo_is_still_running(self):
        self.unload()
        self.assertEqual(['api.shutdown', 'api.server_close', 'demo.shutdown', 'demo.server_close', 'viewer.dispose'], self.trace)

    def test_unload_with_no_api_still_closes_demo(self):
        self.options.api_httpd = None
        self.options.api_httpd_thread = None
        self.unload()
        self.assertEqual(['demo.shutdown', 'demo.server_close', 'viewer.dispose'], self.trace)

    def test_registration_identifies_version_without_changing_action_or_tab_names(self):
        version_statement = re.search(r'^CPH_VERSION = .+$', self.source, re.M).group(0)
        namespace = dict(install_log_filter=lambda logger: None)
        exec(compile(version_statement, str(SOURCE_PATH) + ':version', 'exec'), namespace)
        main_tab_type = type('LiveMainTab', (), {})
        namespace['MainTab'] = main_tab_type
        received_main_tabs = []
        def start_api(options, logger, main_tab, **kwargs):
            received_main_tabs.append(main_tab())
            return self.api, self.api_thread
        namespace['start_cph_api'] = start_api
        exec(compile(production_method(self.source, 'registerExtenderCallbacks'), str(SOURCE_PATH) + ':registration', 'exec'), namespace)
        exec(compile(production_method(self.source, 'getActionName'), str(SOURCE_PATH) + ':actionName', 'exec'), namespace)
        names, output = [], []
        callbacks = SimpleNamespace(getHelpers=lambda: object(), setExtensionName=names.append,
            registerContextMenuFactory=lambda value: None, registerExtensionStateListener=lambda value: None,
            registerHttpListener=lambda value: None, registerSessionHandlingAction=lambda value: None,
            addSuiteTab=lambda value: None, printOutput=output.append)
        self.extender.logger = SimpleNamespace(info=lambda value: None)
        namespace['registerExtenderCallbacks'](self.extender, callbacks)
        self.assertEqual([main_tab_type], received_main_tabs)
        self.assertEqual(['Custom Parameter Handler -re v0.3'], names)
        self.assertEqual(['[Custom Parameter Handler -re v0.3] Local API server started on http://127.0.0.1:17866'], output)
        self.assertEqual('CPH: extract replace value from the final macro response', namespace['getActionName'](self.extender))
        self.assertIn("'CPH Config -re'", self.source)


if __name__ == '__main__':
    unittest.main()
