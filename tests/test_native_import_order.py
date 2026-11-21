"""Execute the production native importer against tab-list doubles; no Burp/network."""
import itertools
import textwrap
import unittest
from collections import OrderedDict
from pathlib import Path


class NativeImportOrderTest(unittest.TestCase):
    def run_import(self, initial, requested, managed=True, original=False, reject_existing_setters=False):
        path = Path(__file__).resolve().parents[1] / 'CustomParamHandler_marged_api_v0.2.py'
        if original: path = path.parents[1] / 'burp-cph' / path.name
        source = path.read_text(encoding='utf-8')
        method = textwrap.dedent(source[source.index('    def load_config('):source.index('    def prepare_to_save_all(')])
        class Config(OrderedDict):
            def keys(self): return list(super().keys())  # Jython 2.7's native keys contract.
        class Name:
            def __init__(self, text): self.text = text
            def getText(self): return self.text
        tabs = []
        class Tab:
            def __init__(self, name=''):
                self.namepane_txtfield = Name(name)
                tabs.append(self)
            @staticmethod
            def move_tab(tab, index):
                tabs.remove(tab)
                tabs.insert(index - 1, tab)
        class Pane:
            def indexOfComponent(self, tab): return tabs.index(tab) + 1
        class Main:
            mainpane = Pane()
            @staticmethod
            def get_config_tabs():
                # Native iterator reads each component's CURRENT index as tabs
                # move, rather than iterating a frozen list in original order.
                components = list(tabs)
                for index in range(1, len(components) + 1):
                    for tab in components:
                        if tabs.index(tab) + 1 == index:
                            yield tab
            @staticmethod
            def get_options_tab(): return options
        class Options:
            CONFIGNAME_OPTIONS = 'options'
            def prepare_to_save_tab(self, tab): return {}
            def set_tab_values(self, config, tab, name=None):
                if reject_existing_setters and tab.namepane_txtfield.text in initial:
                    raise AssertionError('untouched native tab was rewritten')
                if name is not None: tab.namepane_txtfield.text = name
        scope = dict(product=itertools.product, MainTab=Main, ConfigTab=Tab, OptionsTab=Options, managed=managed,
                     same_native_config=lambda a,b: a == b)
        exec(compile(method, '<production native load_config>', 'exec'), scope)
        options = Options()
        for name in initial: Tab(name)
        scope['load_config'](options, Config((name, {}) for name in requested), False)
        return [tab.namepane_txtfield.getText() for tab in tabs]

    def test_existing_two_disabled_job_groups_and_new_group_follow_requested_order(self):
        initial = ['old-a-' + str(i) for i in range(3)] + ['old-b-' + str(i) for i in range(5)]
        requested = ['new-' + str(i) for i in range(5)] + initial
        self.assertEqual(requested, self.run_import(initial, requested))

    def test_managed_import_moves_unchanged_tabs_without_rewriting_native_widgets(self):
        self.assertEqual(['new', 'b', 'a'], self.run_import(['a', 'b'], ['new', 'b', 'a'], reject_existing_setters=True))

    def test_requested_order_is_independent_of_existing_tab_permutation(self):
        requested = ['source', 'destination', 'existing-one', 'existing-two']
        for initial in itertools.permutations(requested):
            with self.subTest(initial=initial):
                self.assertEqual(requested, self.run_import(initial, requested))

    def test_unlisted_existing_tabs_are_kept_after_requested_tabs_in_their_order(self):
        self.assertEqual(['new', 'b', 'a', 'c'], self.run_import(['a', 'b', 'c'], ['new', 'b']))

    def test_legacy_mode_retains_original_ordering_behavior(self):
        initial = ['old-a-' + str(i) for i in range(3)] + ['old-b-' + str(i) for i in range(5)]
        requested = ['new-' + str(i) for i in range(5)] + initial
        self.assertEqual(self.run_import(initial, requested, original=True), self.run_import(initial, requested, managed=False))


if __name__ == '__main__': unittest.main()
