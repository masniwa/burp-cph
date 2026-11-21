# -*- coding: utf-8 -*-

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
from CPH_Managed import authorized, managed, install_log_filter, safe_error, connection_metadata
from CPH_Activity import snapshot as activity_snapshot
from CPH_Validation import validate_config, CphValidationError
try:
    long
except NameError:
    long = int
from threading import Thread, RLock
from json import loads, dumps
from collections import OrderedDict as odict
import re
_configuration_lock = RLock()


class CphAtomicError(ValueError):
    def __init__(self, code, stage, cause=None, tab_name=None, field_name=None):
        ValueError.__init__(self, code)
        self.code = code
        self.stage = stage
        self.cause = cause
        self.tab_name = tab_name
        self.field_name = field_name


def ordered_unique_pairs(pairs):
    result = odict(pairs)
    if len(result) != len(pairs):
        raise CphAtomicError('CPH_DUPLICATE_JSON_KEY', 'parse')
    return result


def managed_import(options_tab, config):
    previous = getattr(options_tab, '_managed_import_active', False)
    options_tab._managed_import_active = True
    try:
        load_config_keep(options_tab, config)
    finally:
        options_tab._managed_import_active = previous


def normalize_native(value):
    """Use the export wire shape when comparing native namedtuple getters to JSON."""
    if isinstance(value, dict):
        return odict((key, normalize_native(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return [normalize_native(item) for item in value]
    try:
        if isinstance(value, unicode):
            return value
    except NameError:
        pass
    if value is None or isinstance(value, (bool, int, long, float, str)):
        return value
    try:
        return str(value)
    except:
        return repr(value)


def same_native_config(actual, expected):
    # Tab order is meaningful; JSON object field order is not. Keep array order, values and missing/null distinct.
    return (list(actual.keys()) == list(expected.keys()) and
            dumps(normalize_native(actual), sort_keys=True) == dumps(normalize_native(expected), sort_keys=True))


def atomic_import(options_tab, main_tab, operation_id, expected, config):
    """Import once on the CPH UI thread and restore the exact pre-import tabs on failure."""
    if not isinstance(operation_id, basestring) or not re.match(r'\A[A-Za-z0-9:_-]{1,200}\Z', operation_id):
        raise CphAtomicError('CPH_OPERATION_ID_INVALID', 'preflight')
    validate_config(expected)
    validate_config(config)
    before = options_tab.prepare_to_save_all()
    if not same_native_config(before, expected):
        raise CphAtomicError('CPH_IMPORT_BASELINE_CHANGED', 'preflight')
    if same_native_config(before, config):
        return
    before_tabs = list(main_tab.get_config_tabs())
    try:
        managed_import(options_tab, config)
        after = options_tab.prepare_to_save_all()
        if not same_native_config(after, config):
            raise CphAtomicError('CPH_IMPORT_READBACK_MISMATCH', 'readback')
        return
    except (Exception, JavaException) as cause:
        try:
            try:
                unchanged = (same_native_config(options_tab.prepare_to_save_all(), before) and
                             list(main_tab.get_config_tabs()) == before_tabs)
            except (Exception, JavaException):
                unchanged = False
            # Removing the selected last tab can select CPH's "+" tab, whose
            # change listener creates a fresh Unconfigured tab. Keep Options
            # selected and remove new tabs from the end of both tab panes.
            # A preflight refusal with exact settings AND tab identity/order is already restored.
            if not unchanged:
                main_tab.mainpane.setSelectedIndex(0)
                for tab in reversed(list(main_tab.get_config_tabs())):
                    if tab not in before_tabs:
                        main_tab.mainpane.remove(tab)
                        options_tab.emv_tab_pane.remove(tab.emv_tab)
                managed_import(options_tab, before)
            restored = options_tab.prepare_to_save_all()
            if not same_native_config(restored, before):
                raise CphAtomicError('CPH_ROLLBACK_READBACK_MISMATCH', 'rollback')
        except (Exception, JavaException):
            raise CphAtomicError('CPH_ROLLBACK_OUTCOME_UNKNOWN', 'rollback', cause)
        raise CphAtomicError(getattr(cause, 'code', 'CPH_IMPORT_FAILED'),
                             getattr(cause, 'stage', 'setter'), cause)


def failure_body(error, operation_id=None):
    result = {'success': False, 'message': safe_error(error),
              'code': getattr(error, 'code', 'CPH_API_FAILED')}
    if operation_id is not None:
        result['operationId'] = operation_id
    stage = getattr(error, 'stage', None)
    if stage is not None:
        result['stage'] = stage
    cause = getattr(error, 'cause', None) or error
    for source, target in [('tab_name', 'tabName'), ('field_name', 'fieldName'),
                           ('exception_class', 'exceptionClass')]:
        value = getattr(cause, source, None)
        if value is not None:
            result[target] = value
    return result

def validate_native_import_shape(config):
    """Reject malformed managed native values before creating any CPH UI tab."""
    if not isinstance(config, dict):
        raise ValueError('CPH_IMPORT_CONFIG_SHAPE_INVALID')
    expression_fields = ('modify_expression', 'match_expression', 'static_expression',
                         'single_expression', 'macro_expression', 'cached_expression')
    socket_fields = ('issuer', 'forwarder')
    boolean_fields = ('enabled', 'auto_encode', 'enable_forwarder', 'dynamic_checkbox')
    integer_fields = ('modify_scope_choice_index', 'modify_type_choice_index',
                      'indices_choice_index', 'extract_choice_index')
    string_fields = ('match_indices', 'single_request', 'single_response')
    for name, tab in config.items():
        if not isinstance(name, basestring) or not isinstance(tab, dict):
            raise ValueError('CPH_IMPORT_TAB_SHAPE_INVALID')
        for key in expression_fields:
            if key in tab and (not isinstance(tab[key], (list, tuple)) or len(tab[key]) != 2 or
                               type(tab[key][0]) is not bool or not isinstance(tab[key][1], basestring)):
                raise ValueError('CPH_IMPORT_EXPRESSION_SHAPE_INVALID')
        for key in socket_fields:
            if key in tab and (not isinstance(tab[key], (list, tuple)) or len(tab[key]) != 3 or
                               type(tab[key][0]) is not bool or not isinstance(tab[key][1], basestring) or
                               type(tab[key][2]) not in (int, long) or not 1 <= tab[key][2] <= 65535):
                raise ValueError('CPH_IMPORT_SOCKET_SHAPE_INVALID')
        for key in boolean_fields:
            if key in tab and type(tab[key]) is not bool:
                raise ValueError('CPH_IMPORT_BOOLEAN_SHAPE_INVALID')
        for key in integer_fields:
            if key in tab and (type(tab[key]) not in (int, long) or tab[key] < 0):
                raise ValueError('CPH_IMPORT_INDEX_SHAPE_INVALID')
        for key in string_fields:
            if key in tab and not isinstance(tab[key], basestring):
                raise ValueError('CPH_IMPORT_TEXT_SHAPE_INVALID')
        if 'cached_selection' in tab and tab['cached_selection'] is not None and not isinstance(tab['cached_selection'], basestring):
            raise ValueError('CPH_IMPORT_CACHE_SHAPE_INVALID')

def load_config_keep(options_tab, config):
    if managed:
        validate_native_import_shape(config)
    before = odict()
    if managed and any(isinstance(tab, dict) and (tab.get('cached_selection') or
                       (tab.get('dynamic_checkbox') is True and tab.get('extract_choice_index') == 2))
                       for tab in config.values()):
        before = normalize_native(options_tab.prepare_to_save_all())
    def definition(tab):
        result = dict(normalize_native(tab))
        result.pop('enabled', None)
        if result.get('dynamic_checkbox') is True and result.get('extract_choice_index') == 0:
            result.pop('single_response', None)
        return result
    def uses_cache(tab):
        return tab.get('dynamic_checkbox') is True and tab.get('extract_choice_index') == 2
    def cache_error(code, stage, name):
        return CphAtomicError(code, stage, tab_name=name, field_name='cached_selection')
    required, visiting = set(), set()
    order = list(config.keys())
    def require_tab(name):
        if name in visiting:
            raise cache_error('CPH_CACHE_REFERENCE_CYCLE', 'preflight', name)
        if name in required:
            return
        if name not in config:
            raise cache_error('CPH_CACHE_REFERENCE_ORDER', 'preflight', name)
        visiting.add(name)
        tab = config[name]
        if uses_cache(tab):
            reference = tab.get('cached_selection')
            if not reference:
                raise cache_error('CPH_CACHE_REFERENCE_REQUIRED', 'preflight', name)
            if reference not in order[:order.index(name)]:
                raise cache_error('CPH_CACHE_REFERENCE_ORDER', 'preflight', name)
            require_tab(reference)
        visiting.remove(name)
        required.add(name)
    if managed:
        for name, tab in config.items():
            if tab.get('enabled', True) or name not in before or definition(tab) != definition(before[name]):
                require_tab(name)
    options_tab.load_config(config, False)
    if not managed:
        return
    # Native multi-tab import can lose cached_selection while moving tabs. Keep
    # configured references even on disabled/static tabs, so later re-enabling
    # retains the approved definition. Reapply only a missing selection.
    cached = [(name, tab) for name, tab in config.items()
              if isinstance(tab, dict) and (tab.get('cached_selection') or
                  (tab.get('enabled', True) and tab.get('dynamic_checkbox') is True
                   and tab.get('extract_choice_index') == 2))]
    if not cached:
        return
    current = options_tab.prepare_to_save_all()
    for name, tab in cached:
        reference = tab.get('cached_selection')
        order = list(current.keys())
        if not uses_cache(tab):
            # STATIC/SINGLE do not consume this reference. Preserve the exact value, including stale names.
            # atomic_import independently checks the complete configuration and order after this repair pass.
            if name in current and current[name].get('cached_selection') == reference:
                continue
            if not reference or name not in current or reference not in order[:order.index(name)]:
                raise cache_error('CPH_IMPORT_READBACK_MISMATCH', 'readback', name)
        # An unchanged inactive dependency may be deliberately incomplete. Preserve it, never repair/delete it.
        if name not in required and name in before and definition(tab) == definition(before[name]) and \
                same_native_config({name: current.get(name)}, {name: tab}):
            continue
        if not reference or name not in current or reference not in order[:order.index(name)]:
            raise cache_error('CPH_CACHE_REFERENCE_ORDER', 'readback', name)
        selection = current[name].get('cached_selection')
        if selection == reference:
            continue
        if selection not in (None, ''):
            raise cache_error('CPH_CACHE_REFERENCE_CONFLICT', 'readback', name)
        options_tab.load_config(odict([(name, tab)]), False)
        current = options_tab.prepare_to_save_all()
        if current.get(name, {}).get('cached_selection') != reference:
            raise cache_error('CPH_CACHE_REFERENCE_NOT_RESTORED', 'readback', name)

def prune_disabled_job_tabs(options_tab, main_tab, names, expected):
    """Remove only explicitly named disabled job tabs on the CPH UI thread."""
    current = options_tab.prepare_to_save_all()
    if not same_native_config(current, expected):
        raise ValueError('CPH_PRUNE_BASELINE_CHANGED')
    if not isinstance(names, list) or not names or len(names) > 1000 or len(names) != len(set(names)):
        raise ValueError('CPH_PRUNE_NAMES_INVALID')
    if any(not isinstance(name, basestring) or not name.startswith('job:') or
           name.count(':') < 2 or name not in current or current[name].get('enabled') is not False
           for name in names):
        raise ValueError('CPH_PRUNE_TARGET_INVALID')
    tabs = {tab.namepane_txtfield.getText(): tab for tab in main_tab.get_config_tabs()}
    if any(name not in tabs for name in names):
        raise ValueError('CPH_PRUNE_TAB_MISSING')
    for name in names:
        tab = tabs[name]
        options_tab.emv_tab_pane.remove(tab.emv_tab)
        main_tab.mainpane.remove(tab)
    after = options_tab.prepare_to_save_all()
    retained = odict((key, value) for key, value in expected.items() if key not in names)
    if not same_native_config(after, retained):
        raise ValueError('CPH_PRUNE_READBACK_MISMATCH')
    return len(names)

try:
    basestring
except NameError:
    basestring = str

def on_ui_thread(function):
    try:
        from javax.swing import SwingUtilities
        from java.util.concurrent import Callable, FutureTask
    except ImportError:
        return function()
    if SwingUtilities.isEventDispatchThread():
        return function()
    class Work(Callable):
        def call(self):
            try:
                return (True, function())
            except (Exception, JavaException) as error:
                # FutureTask wraps Python exceptions in ExecutionException and
                # loses the safe code/stage fields needed by the managed caller.
                return (False, error)
    task = FutureTask(Work())
    SwingUtilities.invokeLater(task)
    succeeded, value = task.get()
    if not succeeded:
        raise value
    return value

try:
    from java.lang import Exception as JavaException
except:
    JavaException = Exception


class CphApiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class CphApiHandler(BaseHTTPRequestHandler):
    options_tab_getter = None
    logger_getter = None
    main_tab_getter = None

    def _send_json(self, code, body):
        payload = dumps(body)
        if not isinstance(payload, bytes):
            payload = payload.encode('utf-8')

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


    def _normalize_for_json(self, value):
        return normalize_native(value)

    def do_GET(self):
        if not authorized(self.headers.get('Authorization')):
            self._send_json(403, {'success': False, 'message': 'CPH_AUTH_REQUIRED'})
            return
        if self.path == '/cph/health':
            self._send_json(200, {
                'success': True,
                'message': 'ok',
                'managed': managed,
                'activity': activity_snapshot(),
                'connection': connection_metadata()
            })
            return

        if self.path == '/cph/export':
            try:
                options_tab = self.__class__.options_tab_getter()
                with _configuration_lock:
                    config = on_ui_thread(options_tab.prepare_to_save_all)
                self._send_json(200, {
                    'success': True,
                    'config': self._normalize_for_json(config),
                    'managed': managed,
                    'activity': activity_snapshot(),
                'connection': connection_metadata()
                })
            except (Exception, JavaException) as e:
                try:
                    logger = self.__class__.logger_getter()
                    if managed:
                        logger.error('CPH API export failed.')
                    else:
                        logger.exception('CPH API export failed.')
                except:
                    pass

                self._send_json(500, {
                    'success': False,
                    'message': safe_error(e)
                })
            return

        self._send_json(404, {
            'success': False,
            'message': 'Not found'
        })

    def do_POST(self):
        if not authorized(self.headers.get('Authorization')):
            self._send_json(403, {'success': False, 'message': 'CPH_AUTH_REQUIRED'})
            return
        if self.path == '/cph/prune':
            if not managed:
                self._send_json(403, {'success': False, 'message': 'CPH_MANAGEMENT_REQUIRED'})
                return
            try:
                content_length = int(self.headers.get('Content-Length', '0'))
                if content_length < 0 or content_length > 16 * 1024 * 1024:
                    self._send_json(413, {'success': False, 'message': 'CPH_BODY_LIMIT'})
                    return
                body = loads(self.rfile.read(content_length), object_pairs_hook=odict)
                if not isinstance(body, dict) or set(body.keys()) != set(['names', 'expected']) or not isinstance(body['expected'], dict):
                    raise ValueError('CPH_PRUNE_ARGUMENTS_INVALID')
                options_tab = self.__class__.options_tab_getter()
                with _configuration_lock:
                    count = on_ui_thread(lambda: prune_disabled_job_tabs(options_tab, self.__class__.main_tab_getter(), body['names'], body['expected']))
                self._send_json(200, {'success': True, 'removedCount': count})
            except (Exception, JavaException) as e:
                try:
                    self.__class__.logger_getter().error('CPH API prune failed.')
                except:
                    pass
                self._send_json(500, {'success': False, 'message': safe_error(e)})
            return
        if self.path == '/cph/import-atomic':
            if not managed:
                self._send_json(403, {'success': False, 'message': 'CPH_MANAGEMENT_REQUIRED'})
                return
            operation_id = None
            try:
                content_length = int(self.headers.get('Content-Length', '0'))
                if content_length < 0 or content_length > 16 * 1024 * 1024:
                    self._send_json(413, {'success': False, 'message': 'CPH_BODY_LIMIT'})
                    return
                body = loads(self.rfile.read(content_length), object_pairs_hook=ordered_unique_pairs)
                if not isinstance(body, dict) or set(body.keys()) != set(['operationId', 'expected', 'config']):
                    raise CphAtomicError('CPH_IMPORT_ARGUMENTS_INVALID', 'preflight')
                candidate_id = body['operationId']
                if not isinstance(candidate_id, basestring) or not re.match(r'\A[A-Za-z0-9:_-]{1,200}\Z', candidate_id):
                    raise CphAtomicError('CPH_OPERATION_ID_INVALID', 'preflight')
                operation_id = candidate_id
                validate_config(body['expected'])
                validate_config(body['config'])
                options_tab = self.__class__.options_tab_getter()
                with _configuration_lock:
                    on_ui_thread(lambda: atomic_import(options_tab, self.__class__.main_tab_getter(), operation_id, body['expected'], body['config']))
                self._send_json(200, {'success': True, 'operationId': operation_id,
                                      'message': 'Configuration imported atomically'})
            except (Exception, JavaException) as e:
                try:
                    self.__class__.logger_getter().error('CPH API atomic import failed.')
                except:
                    pass
                self._send_json(500, failure_body(e, operation_id))
            return
        if self.path != '/cph/import':
            self._send_json(404, {
                'success': False,
                'message': 'Not found'
            })
            return

        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            if content_length < 0 or content_length > 16 * 1024 * 1024:
                self._send_json(413, {'success': False, 'message': 'CPH_BODY_LIMIT'})
                return
            raw_body = self.rfile.read(content_length)
            config = loads(raw_body, object_pairs_hook=ordered_unique_pairs if managed else odict)

            if managed:
                validate_config(config)

            options_tab = self.__class__.options_tab_getter()
            logger = self.__class__.logger_getter()

            # keep mode
            with _configuration_lock:
                on_ui_thread(lambda: managed_import(options_tab, config) if managed else load_config_keep(options_tab, config))

            try:
                logger.info('Configuration imported via CPH API with keep mode.')
            except:
                pass

            self._send_json(200, {
                'success': True,
                'message': 'Configuration imported with keep mode'
            })

        except (Exception, JavaException) as e:
            try:
                logger = self.__class__.logger_getter()
                if managed:
                    logger.error('CPH API import failed.')
                else:
                    logger.exception('CPH API import failed.')
            except:
                pass

            self._send_json(500, failure_body(e))

    def log_message(self, format, *args):
        return


def start_cph_api(options_tab_getter, logger_getter, main_tab_getter, host='127.0.0.1', port=17866):
    if managed and host != '127.0.0.1':
        raise ValueError('CPH_MANAGED_LOOPBACK_REQUIRED')
    install_log_filter(logger_getter())
    CphApiHandler.options_tab_getter = staticmethod(options_tab_getter)
    CphApiHandler.logger_getter = staticmethod(logger_getter)
    CphApiHandler.main_tab_getter = staticmethod(main_tab_getter)

    httpd = CphApiThreadedHTTPServer((host, port), CphApiHandler)
    thread = Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        logger_getter().info('CPH API server started on %s:%s' % (host, port))
    except:
        pass

    return httpd, thread
