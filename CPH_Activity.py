# -*- coding: utf-8 -*-
"""Process-local CPH lifecycle observations. Does not infer network or Macro completion."""
from functools import wraps
from threading import RLock
from uuid import uuid4

_lock = RLock()
_epoch = str(uuid4())
_active = {'http_handler': 0, 'helper_send': 0}
_started = 0
_finished = 0


def tracked(kind):
    if kind not in _active:
        raise ValueError('UNKNOWN_ACTIVITY_KIND')

    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            global _started, _finished
            with _lock:
                _active[kind] += 1
                _started += 1
            try:
                return function(*args, **kwargs)
            finally:
                with _lock:
                    _active[kind] -= 1
                    _finished += 1
        return call
    return decorate


def snapshot():
    with _lock:
        return {'epoch': _epoch, 'active': dict(_active),
                'started': _started, 'finished': _finished,
                'coverage': 'CPH_HTTP_HANDLER_AND_SYNCHRONOUS_HELPER_ONLY'}