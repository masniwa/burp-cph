# >> 20261008 mniwa Regress editor rendering and selection recovery with Jython and real headless Swing components.
from collections import namedtuple
from difflib import unified_diff
from datetime import datetime
import os
import sys
import unittest
from java.lang import Runnable
from java.awt import GridBagLayout, GridBagConstraints
from javax.swing import JPanel, JSplitPane, JTable, JScrollPane, SwingUtilities
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel


class Editor(object):
    def __init__(self):
        self.component = JPanel()
        self.messages = []
        self.fail = False

    def getComponent(self):
        return self.component

    def setMessage(self, message, is_request):
        if self.fail:
            raise RuntimeError('Injected rendering failure')
        self.messages.append((message, is_request))


class Callbacks(object):
    def createMessageEditor(self, controller, editable):
        return Editor()


class Cph(object):
    callbacks = Callbacks()


class MainTab(object):
    _cph = Cph()


source_path = os.environ.get('CPH_TEST_SOURCE', os.path.join(os.path.dirname(__file__), '..', 'CustomParamHandler_marged_api_v0.2.py'))
with open(source_path, 'rb') as stream:
    source = stream.read()
start = source.index('class EMVTab(')
end = source.index('class ConfigTabTitle(', start)
# Load the production viewer unchanged, without starting Burp or its HTTP API.
exec(compile('\n' * source[:start].count('\n') + source[start:end], source_path, 'exec'))


class ViewerTest(unittest.TestCase):
    def setUp(self):
        self.viewer = EMVTab()

    def add(self, original='before\r\n', modified='after\r\n', request=True):
        self.viewer.add_table_row(datetime.now(), request, original, modified)

    def test_render_uses_public_component_and_correct_messages(self):
        self.add()
        self.assertEqual('before\r\n', self.viewer.original_field.messages[-1][0])
        self.assertEqual('after\r\n', self.viewer.modified_field.messages[-1][0])
        self.assertTrue(self.viewer.diff_field.messages[-1][1])
        self.assertIn('-before', self.viewer.diff_field.messages[-1][0])
        self.assertIn('+after', self.viewer.diff_field.messages[-1][0])
        self.assertEqual(self.viewer.diff_field.component, self.viewer.diffpane.getTopComponent())
        self.assertFalse(self.viewer.updating)

    def test_new_rows_refresh_same_selected_index_and_preserve_response_flag(self):
        self.add()
        self.add('old response', 'new response', False)
        self.assertEqual(('new response', False), self.viewer.modified_field.messages[-1])
        self.assertFalse(self.viewer.updating)

    def test_empty_or_cleared_selection_is_safe(self):
        self.viewer.valueChanged(None)
        self.assertFalse(self.viewer.updating)
        self.add()
        self.viewer.table.clearSelection()
        self.viewer.valueChanged(None)
        self.assertEqual(-1, self.viewer.selected_index)
        self.assertFalse(self.viewer.updating)

    def test_render_exception_releases_guard_and_allows_retry(self):
        self.add()
        self.viewer.selected_index = -1
        self.viewer.diff_field.fail = True
        self.assertRaises(RuntimeError, self.viewer.valueChanged, None)
        self.assertFalse(self.viewer.updating)
        self.viewer.diff_field.fail = False
        self.viewer.valueChanged(None)
        self.assertEqual(0, self.viewer.selected_index)
        self.assertFalse(self.viewer.updating)

    def test_history_retention_and_latest_message(self):
        for number in range(40):
            self.add('old-' + str(number), 'new-' + str(number))
        self.assertEqual(32, len(self.viewer.table_model.rows))
        self.assertEqual(32, len(self.viewer.table_model.messages))
        self.assertEqual('new-39', self.viewer.modified_field.messages[-1][0])
        self.assertFalse(self.viewer.updating)


class RunTests(Runnable):
    def run(self):
        global result
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ViewerTest))


if __name__ == '__main__':
    SwingUtilities.invokeAndWait(RunTests())
    sys.exit(0 if result.wasSuccessful() else 1)
# << mniwa
