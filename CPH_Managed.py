# -*- coding: utf-8 -*-
"""Opt-in management boundary. No HTTP or Burp operation occurs when this module is imported."""
import os
import logging
import json
import codecs

def configuration(environment=None, directory=None):
    environment = os.environ if environment is None else environment
    if 'BURP_DIAG_MANAGED' in environment:
        enabled = environment.get('BURP_DIAG_MANAGED') == '1'
        token = environment.get('BURP_DIAG_CPH_TOKEN', '')
        metadata = {'source': 'environment', 'runtimeDirectory': None}
    else:
        directory = directory or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'runtime')
        connection = os.path.join(directory, 'cph-connection.json')
        if os.path.isfile(connection):
            try:
                with codecs.open(connection, 'r', 'utf-8-sig') as handle:
                    target = json.load(handle)['runtimeDirectory']
                if not isinstance(target, type(u'')) and not isinstance(target, str):
                    raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
                if not target.strip():
                    raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
                directory = os.path.normpath(os.path.join(directory, target))
            except Exception:
                raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
        settings = os.path.join(directory, 'settings.json')
        secrets = os.path.join(directory, 'operator-secrets.json')
        # An explicit connection is a managed installation, never an invitation
        # to silently start unauthenticated after a directory is renamed.
        if os.path.isfile(connection) and (not os.path.isfile(settings) or not os.path.isfile(secrets)):
            raise ValueError('CPH_RUNTIME_PROFILE_MISSING: run configure-runtime.ps1 with the selected MCP JAR before loading CPH')
        enabled = os.path.isfile(settings) or os.path.isfile(secrets)
        metadata = {'source': 'file' if enabled else 'standalone',
                    'runtimeDirectory': os.path.abspath(directory) if enabled else None}
        token = ''
        if enabled:
            try:
                if os.path.islink(directory) or os.path.islink(secrets) or not os.path.isfile(settings):
                    raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
                with codecs.open(secrets, 'r', 'utf-8-sig') as handle:
                    values = json.load(handle)
                token = values.get('cph', '')
                if token == values.get('worker'):
                    raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
            except Exception:
                raise ValueError('CPH_RUNTIME_PROFILE_INVALID')
    if enabled and len(token) < 32:
        raise ValueError('CPH_MANAGED_TOKEN_REQUIRED')
    return enabled, token, metadata

def load_configuration(environment=None, directory=None):
    enabled, token, unused_metadata = configuration(environment, directory)
    return enabled, token

managed, _token, _connection_metadata = configuration()

def connection_metadata():
    # Report the STARTUP selection, not a fresh file read that could disagree
    # with the credential retained by this process. Never return credential data.
    return dict(_connection_metadata)

def authorized(header):
    if not managed:
        return True
    expected = 'Bearer ' + _token
    supplied = header or ''
    # Works in Jython 2.7 as well as CPython. Never disclose the expected token in an error.
    difference = len(expected) ^ len(supplied)
    for index in range(len(expected)):
        difference |= ord(expected[index]) ^ (ord(supplied[index]) if index < len(supplied) else 0)
    return difference == 0

class ManagedLogFilter(logging.Filter):
    def filter(self, record):
        # Legacy debug/warning paths include matched secrets and full messages. Keep severity only.
        record.msg = 'CPH managed event; sensitive details withheld'
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        return True

def install_log_filter(logger):
    if managed and not any(isinstance(item, ManagedLogFilter) for item in logger.filters):
        logger.addFilter(ManagedLogFilter())

def safe_error(error):
    return 'CPH_API_FAILED' if managed else str(error)
