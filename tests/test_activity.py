"""Pure lifecycle tests. No Burp, configuration, HTTP or JVM startup."""
import unittest
from threading import Event, Thread
from CPH_Activity import tracked, snapshot


class ActivityTest(unittest.TestCase):
    def test_nested_handler_and_helper_restore_counters_after_exception(self):
        before = snapshot()

        @tracked('helper_send')
        def helper():
            observed = snapshot()
            self.assertEqual(before['active']['http_handler'] + 1, observed['active']['http_handler'])
            self.assertEqual(before['active']['helper_send'] + 1, observed['active']['helper_send'])
            raise ValueError('fixture')

        @tracked('http_handler')
        def handler():
            helper()

        with self.assertRaises(ValueError):
            handler()
        after = snapshot()
        self.assertEqual(before['active'], after['active'])
        self.assertEqual(before['started'] + 2, after['started'])
        self.assertEqual(before['finished'] + 2, after['finished'])
        self.assertEqual(before['epoch'], after['epoch'])

    def test_snapshot_observes_current_helper_without_waiting_for_it(self):
        entered, release = Event(), Event()

        @tracked('helper_send')
        def helper():
            entered.set()
            release.wait(5)

        before = snapshot()
        worker = Thread(target=helper)
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            observed = snapshot()
            self.assertEqual(before['active']['helper_send'] + 1, observed['active']['helper_send'])
            observed['active']['helper_send'] = 999
            self.assertNotEqual(999, snapshot()['active']['helper_send'])
        finally:
            release.set()
            worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(before['active'], snapshot()['active'])


if __name__ == '__main__':
    unittest.main()