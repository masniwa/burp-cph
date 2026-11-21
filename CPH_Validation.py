# -*- coding: utf-8 -*-
"""Pure native CPH setter-shape checks; no Burp imports or request values in errors."""
from hashlib import sha256

try:
    basestring
except NameError:
    basestring = str

OPTIONS_NAME = sha256(b'options').hexdigest()
BOOLEAN_FIELDS = set(['enabled', 'auto_encode', 'enable_forwarder', 'dynamic_checkbox'])
OPTION_BOOLEAN_FIELDS = set(['chkbox_proxy', 'chkbox_target', 'chkbox_spider', 'chkbox_repeater',
                             'chkbox_sequencer', 'chkbox_intruder', 'chkbox_scanner', 'chkbox_extender'])
INDICES = {'modify_scope_choice_index': 1, 'modify_type_choice_index': 2,
           'indices_choice_index': 2, 'extract_choice_index': 2}
EXPRESSIONS = set(['modify_expression', 'match_expression', 'static_expression',
                   'single_expression', 'macro_expression', 'cached_expression'])
SOCKETS = set(['forwarder', 'issuer'])
STRINGS = set(['match_indices', 'single_request', 'single_response'])


class CphValidationError(ValueError):
    def __init__(self, code, tab_name, field_name):
        ValueError.__init__(self, code)
        self.code = code
        self.tab_name = tab_name
        self.field_name = field_name


def _fail(code, name, field):
    raise CphValidationError(code, name, field)


def _integer(value, lower, upper):
    return type(value) in (int, long) and lower <= value <= upper


try:
    long
except NameError:
    long = int


def validate_config(config):
    if not isinstance(config, dict):
        _fail('CPH_FIELD_SHAPE_INVALID', '(config)', '(root)')
    if len(config) > 1000:
        _fail('CPH_FIELD_SHAPE_INVALID', '(config)', '(count)')
    for name, tab in config.items():
        if not isinstance(name, basestring) or not name or len(name) > 160 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
            _fail('CPH_TAB_NAME_INVALID', '(tab)', '(name)')
        if not isinstance(tab, dict):
            _fail('CPH_FIELD_SHAPE_INVALID', name, '(tab)')
        options = name == OPTIONS_NAME
        known = OPTION_BOOLEAN_FIELDS | set(['verbosity']) if options else BOOLEAN_FIELDS | set(INDICES) | EXPRESSIONS | SOCKETS | STRINGS | set(['cached_selection'])
        for field, value in tab.items():
            if field not in known:
                _fail('UNSUPPORTED_CPH_FIELD', name, field)
            if field in OPTION_BOOLEAN_FIELDS or field in BOOLEAN_FIELDS:
                if type(value) is not bool:
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
            elif field == 'verbosity':
                if not _integer(value, 1, 4):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
            elif field in INDICES:
                if not _integer(value, 0, INDICES[field]):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
            elif field in EXPRESSIONS:
                if not isinstance(value, list) or len(value) != 2 or type(value[0]) is not bool or not isinstance(value[1], basestring):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
                if field == 'static_expression' and ('\r' in value[1] or '\n' in value[1]):
                    _fail('CPH_SINGLE_LINE_CONTROL_CHARACTER', name, field)
            elif field in SOCKETS:
                if not isinstance(value, list) or len(value) != 3 or type(value[0]) is not bool or not isinstance(value[1], basestring) or not _integer(value[2], 1, 65535):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
            elif field in STRINGS:
                if not isinstance(value, basestring):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
                if field == 'match_indices' and ('\r' in value or '\n' in value):
                    _fail('CPH_SINGLE_LINE_CONTROL_CHARACTER', name, field)
            elif field == 'cached_selection':
                if value is not None and not isinstance(value, basestring):
                    _fail('CPH_FIELD_SHAPE_INVALID', name, field)
                if value is not None and ('\r' in value or '\n' in value):
                    _fail('CPH_SINGLE_LINE_CONTROL_CHARACTER', name, field)
