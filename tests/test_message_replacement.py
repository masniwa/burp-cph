# -*- coding: utf-8 -*-
"""Actual replacement method in CPython and Jython, without importing Burp or HTTP."""
import os
import re
import textwrap
import unittest


class Value(object):
    def __init__(self, value): self.value = value
    def getText(self): return self.value
    def getSelectedItem(self): return self.value
    def isSelected(self): return self.value


class Logger(object):
    def __init__(self): self.errors = []
    def debug(self, *args): pass
    def warning(self, *args): pass
    def error(self, *args): self.errors.append(args)


class ReplacementTest(unittest.TestCase):
    def run_replacement(self, message='PLACEHOLDER', target='PLACEHOLDER',
                        replacement=r'\g<token>', source='abc123',
                        extraction=r'(?s)(?P<token>.*)', dynamic=True,
                        indices='0', mode='cached'):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'CustomParamHandler_marged_api_v0.2.py')
        with open(path, 'rb') as handle:
            source_code = handle.read().decode('utf-8').replace('\r\n', '\n')
        method = textwrap.dedent(source_code[source_code.index('    def modify_message('):])
        class Main(object):
            @staticmethod
            def get_config_tab_cache(name): return ('source-request', source)
        namespace = {'MainTab': Main}
        for name in ['compile', 'sub', 'findall', 'finditer', 'match', 'search', 'split', 'error']:
            namespace['re_' + name] = getattr(re, name)
        eval(compile(method, '<production modify_message>', 'exec'), namespace)

        class Helpers(object):
            def bytesToString(self, value): return value
        class Extender(object):
            logger = Logger()
            helpers = Helpers()
            final_macro_resp = source
            issued = 0
            def issue_request(self, tab):
                self.issued += 1
                tab.response = source
        class Tab(object):
            PARAM_HANDL_COMBO_EXTRACT_CACHED = 'cached'
            PARAM_HANDL_COMBO_EXTRACT_SINGLE = 'single'
            PARAM_HANDL_COMBO_EXTRACT_MACRO = 'macro'
            param_handl_txtfield_match_indices = Value(indices)
            param_handl_exp_pane_target = target
            param_handl_exp_pane_extract_static = replacement
            param_handl_exp_pane_extract_single = extraction
            param_handl_exp_pane_extract_macro = extraction
            param_handl_exp_pane_extract_cached = extraction
            param_handl_dynamic_chkbox = Value(dynamic)
            param_handl_combo_extract = Value(mode)
            param_handl_combo_cached = Value('source')
            namepane_txtfield = Value('fixture')
            def get_exp_pane_expression(self, expression): return expression
        extender = Extender()
        result = namespace['modify_message'](extender, Tab(), message)
        return result, extender

    def check(self, expected, **kwargs):
        result, extender = self.run_replacement(**kwargs)
        self.assertEqual(expected, result)
        return extender

    def test_dynamic_regex_metacharacters_are_literal_data(self):
        for value in ['a+b', '(', '[x]', '{2}', 'a.*?', '^start$', 'one|two', 'back\\slash']:
            self.check(value, source=value)

    def test_unicode_and_all_byte_values_are_preserved(self):
        self.check(u'日本語+\\g<token>$', source=u'日本語+\\g<token>$')
        try:
            character = unichr
        except NameError:
            character = chr
        value = ''.join(character(index) for index in range(256))
        self.check(value, source=value)

    def test_multiple_source_groups_follow_declaration_order(self):
        self.check('a+b:($):a+b:($)', source='a+b|($)',
                   extraction=r'(?P<first>[^|]+)\|(?P<second>.*)',
                   replacement=r'\g<first>:\g<second>:\1:\2')

    def test_unmatched_optional_source_group_is_empty(self):
        self.check('a+b::', source='a+b',
                   extraction=r'(?P<first>[^|]+)(?:\|(?P<second>.*))?',
                   replacement=r'\g<first>:\g<second>:\2')

    def test_static_noncapturing_group_retains_pattern_semantics(self):
        self.check('ok ok baz', message='foo bar baz', target=r'(?:foo|bar)',
                   replacement='ok', dynamic=False, indices='0:-1,-1')

    def test_static_lookaround_retains_original_context(self):
        self.check('start:bar:end', message='start:foo:end',
                   target=r'(?<=start:)(foo)(?=:end)', replacement='bar', dynamic=False)

    def test_static_named_numeric_and_whole_match_backreferences(self):
        self.check('12:foo:foo12', message='foo12', target=r'(?P<word>foo)([0-9]+)',
                   replacement=r'\2:\g<word>:\g<0>', dynamic=False)

    def test_dynamic_values_coexist_with_target_backreferences(self):
        self.check('HOLDER:PLACE:a+b:a+b:PLACEHOLDER',
                   target=r'(?P<head>PLACE)(HOLDER)', source='a+b',
                   replacement=r'\2:\g<head>:\g<token>:\3:\g<0>')

    def test_dynamic_lookaround_and_anchors_are_not_rewritten(self):
        self.check('start:a+b:end', message='start:foo:end',
                   target=r'(?<=start:)foo(?=:end)', source='a+b')
        self.check('a+b', message='foo', target=r'^foo$', source='a+b')

    def test_inline_multiline_and_case_flags_are_preserved(self):
        self.check('bar\nbar', message='FOO\nfoo', target=r'(?im)^foo$',
                   replacement='bar', dynamic=False, indices='0:-1,-1')

    def test_verbose_flags_and_comments_are_preserved(self):
        self.check('a+b', message='foo', target='(?x) ^ foo $ # end comment', source='a+b')
        self.check('bar', message='foo', target='(?x) ^ (?:foo) $ # end comment',
                   replacement='bar', dynamic=False)

    def test_escaped_dynamic_reference_stays_literal(self):
        self.check('\\g<token>|a+b|\\a+b', source='a+b',
                   replacement=r'\\g<token>|\g<token>|\\\g<token>')

    def test_octal_escape_is_not_mistaken_for_dynamic_group_reference(self):
        self.check('A:a+b:a+b:a+b', target=r'(PLACE)(HOLDER)', source='a+b',
                   replacement=r'\101:\3:\g<3>:\g<003>')

    def test_match_indices_are_deduplicated_and_applied_in_message_order(self):
        self.check('Y X Y Y', message='X X X X', target='X', replacement='Y',
                   dynamic=False, indices='2,0,2,-1')

    def test_negative_indices_and_slices_are_preserved(self):
        self.check('X Y Y Y', message='X X X X', target='X', replacement='Y',
                   dynamic=False, indices='-3:-1,-1')
        self.check('Y X X X', message='X X X X', target='X', replacement='Y',
                   dynamic=False, indices='-100,100,0')

    def test_replacements_are_not_matched_again(self):
        self.check('foofoo foofoo', message='foo foo', target='foo', replacement='foofoo',
                   dynamic=False, indices='0:-1,-1')

    def test_zero_width_matches_keep_spans(self):
        self.check('|ab|', message='ab', target='^|$', replacement='|',
                   dynamic=False, indices='0:-1,-1')

    def test_source_first_match_is_retained(self):
        self.check('first', source='token=first token=second', extraction=r'token=(?P<token>\S+)')

    def test_all_dynamic_sources_use_same_literal_value_handling(self):
        for mode in ['cached', 'single', 'macro']:
            extender = self.check('a+b', source='a+b', mode=mode)
            self.assertEqual(1 if mode == 'single' else 0, extender.issued)

    def test_malformed_expressions_and_references_leave_original_message(self):
        self.check('PLACEHOLDER', target='(')
        self.check('PLACEHOLDER', extraction='(')
        self.check('PLACEHOLDER', replacement=r'\g<missing>')
        self.check('PLACEHOLDER', replacement='\\')
        self.check('PLACEHOLDER', replacement=r'\9')
        self.check('PLACEHOLDER', replacement=u'\\g<²>')

    def test_duplicate_source_and_target_names_do_not_partially_modify_message(self):
        self.check('PLACEHOLDER', target=r'(?P<token>PLACEHOLDER)', source='new')

    def test_unmatched_target_and_empty_cache_do_not_issue_helper_request(self):
        extender = self.check('other', message='other', mode='single')
        self.assertEqual(0, extender.issued)
        self.check('PLACEHOLDER', source='')


if __name__ == '__main__':
    unittest.main()
