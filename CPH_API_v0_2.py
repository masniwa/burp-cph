# -*- coding: utf-8 -*-

try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn
except ImportError:
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
from CPH_Managed import authorized, managed, install_log_filter, safe_error, connection_metadata
try:
    long
except NameError:
    long = int
from threading import Thread, RLock
from json import loads, dumps
from collections import OrderedDict as odict
_configuration_lock = RLock()

def load_config_keep(options_tab, config):
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
        if not reference or name not in current or reference not in order[:order.index(name)]:
            raise ValueError('CPH_CACHE_REFERENCE_ORDER')
        selection = current[name].get('cached_selection')
        if selection == reference:
            continue
        if selection not in (None, ''):
            raise ValueError('CPH_CACHE_REFERENCE_CONFLICT')
        options_tab.load_config(odict([(name, tab)]), False)
        current = options_tab.prepare_to_save_all()
        if current.get(name, {}).get('cached_selection') != reference:
            raise ValueError('CPH_CACHE_REFERENCE_NOT_RESTORED')

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
            return function()
    task = FutureTask(Work())
    SwingUtilities.invokeLater(task)
    return task.get()

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
        if isinstance(value, dict):
            # OrderedDict is required on Jython 2.7; ordinary dict destroys semantic CPH tab order.
            return odict((k, self._normalize_for_json(v)) for k, v in value.items())
        if isinstance(value, (list, tuple)):
            return [self._normalize_for_json(v) for v in value]
        try:
            if isinstance(value, unicode):
                return value
        except:
            pass
        if value is None or isinstance(value, (bool, int, long, float, str)):
            return value
        try:
            return str(value)
        except:
            return repr(value)

    def do_GET(self):
        if not authorized(self.headers.get('Authorization')):
            self._send_json(403, {'success': False, 'message': 'CPH_AUTH_REQUIRED'})
            return
        if self.path == '/cph/health':
            self._send_json(200, {
                'success': True,
                'message': 'ok',
                'managed': managed,
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
            config = loads(raw_body, object_pairs_hook=odict)

            options_tab = self.__class__.options_tab_getter()
            logger = self.__class__.logger_getter()

            # keep mode
            with _configuration_lock:
                on_ui_thread(lambda: load_config_keep(options_tab, config))

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

            self._send_json(500, {
                'success': False,
                'message': safe_error(e)
            })

    def log_message(self, format, *args):
        return


def start_cph_api(options_tab_getter, logger_getter, host='127.0.0.1', port=17866):
    if managed and host != '127.0.0.1':
        raise ValueError('CPH_MANAGED_LOOPBACK_REQUIRED')
    install_log_filter(logger_getter())
    CphApiHandler.options_tab_getter = staticmethod(options_tab_getter)
    CphApiHandler.logger_getter = staticmethod(logger_getter)

    httpd = CphApiThreadedHTTPServer((host, port), CphApiHandler)
    thread = Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        logger_getter().info('CPH API server started on %s:%s' % (host, port))
    except:
        pass

    return httpd, thread
