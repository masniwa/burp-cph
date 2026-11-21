"""Actual definition accessors, with a lagging/reset read-only editor; no Burp/network."""
import textwrap
import unittest
from pathlib import Path


class ResponseDefinitionTest(unittest.TestCase):
    def fixture(self, managed=True):
        source=(Path(__file__).resolve().parents[1]/'CustomParamHandler_marged_api_v0.2.py').read_text(encoding='utf-8')
        methods=textwrap.dedent(source[source.index('    def get_single_response('):source.index('    def initialize_req_resp(')])
        class Helpers:
            def bytesToString(self,value):return value.decode('latin1')
            def stringToBytes(self,value):return value.encode('latin1')
        class Cph:helpers=Helpers()
        class Main:_cph=Cph()
        class Viewer:
            def __init__(self):self.message=b'old-view';self.received=None
            def getMessage(self):return self.message
            def setMessage(self,value,is_request):self.received=value  # asynchronous native view
        class Tab:
            response=b'initial-model'
            param_handl_response_editor=Viewer()
        namespace=dict(MainTab=Main,managed=managed)
        exec(compile(methods,'<native response definition accessors>','exec'),namespace)
        Tab.get_single_response=namespace['get_single_response'];Tab.set_single_response=namespace['set_single_response']
        return Tab(),source

    def test_imported_full_response_survives_delayed_or_reset_view(self):
        tab,_=self.fixture()
        value='HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nfull-sample'
        tab.set_single_response(value)
        self.assertEqual(value,tab.get_single_response())
        tab.param_handl_response_editor.message=b' \r\n'*6
        self.assertEqual(value,tab.get_single_response())
        self.assertEqual(value.encode('latin1'),tab.param_handl_response_editor.received)

    def test_live_single_response_updates_export_without_waiting_for_view(self):
        tab,_=self.fixture();tab.set_single_response('imported')
        tab.response=b'HTTP/1.1 200 OK\r\n\r\ncurrent response'
        self.assertEqual(tab.response.decode('latin1'),tab.get_single_response())

    def test_binary_sample_uses_existing_byte_string_conversion(self):
        tab,_=self.fixture();value='HTTP/1.1 200 OK\r\n\r\n'+bytes(range(256)).decode('latin1')
        tab.set_single_response(value)
        self.assertEqual(value,tab.get_single_response())

    def test_legacy_profile_retains_native_view_getter_and_setter_behavior(self):
        tab,_=self.fixture(False);tab.set_single_response('new definition')
        self.assertEqual('old-view',tab.get_single_response())
        self.assertEqual(b'initial-model',tab.response)

    def test_config_mechanism_uses_the_authoritative_accessors(self):
        _,source=self.fixture()
        fragment=source.split("'single_response',",1)[1].split('SubTab.CONFIG_MECHANISM(',1)[0]
        self.assertIn('self.get_single_response',fragment);self.assertIn('self.set_single_response',fragment)


if __name__=='__main__':unittest.main()
