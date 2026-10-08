# -*- coding: utf-8 -*-

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from threading import Thread
from json import loads, dumps
from collections import OrderedDict as odict

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
        if not isinstance(payload, str):
            payload = str(payload)

        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != '/cph/import':
            self._send_json(404, {
                'success': False,
                'message': 'Not found'
            })
            return

        try:
            content_length = int(self.headers.getheader('Content-Length', '0'))
            raw_body = self.rfile.read(content_length)
            config = loads(raw_body, object_pairs_hook=odict)

            options_tab = self.__class__.options_tab_getter()
            logger = self.__class__.logger_getter()

            # keep mode
            options_tab.load_config(config, False)

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
                logger.exception('CPH API import failed.')
            except:
                pass

            self._send_json(500, {
                'success': False,
                'message': str(e)
            })

    def log_message(self, format, *args):
        return


def start_cph_api(options_tab_getter, logger_getter, host='127.0.0.1', port=17865):
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
