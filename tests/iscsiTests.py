import os
from contextlib import contextmanager

from monkeypatch import MonkeyPatch
from testlib import VdsmTestCase as TestCaseBase
from testlib import make_config

from vdsm import utils

from storage import iscsi
from storage import iscsiadm


def fake_rescan(timeout):
    def func():
        proc = utils.execCmd(["sleep", str(timeout)], sync=False)
        return utils.AsyncProcessOperation(proc)
    return func


class RescanTimeoutTests(TestCaseBase):

    @contextmanager
    def assertMaxDuration(self, maxtime):
        start = utils.monotonic_time()
        try:
            yield
        finally:
            elapsed = utils.monotonic_time() - start
            if maxtime < elapsed:
                self.fail("Operation was too slow %.2fs > %.2fs" %
                          (elapsed, maxtime))

    @MonkeyPatch(iscsiadm, 'session_rescan_async', fake_rescan(0.1))
    def testWait(self):
        with self.assertMaxDuration(0.3):
            iscsi.rescan()

    @MonkeyPatch(iscsiadm, 'session_rescan_async', fake_rescan(2))
    @MonkeyPatch(iscsi, 'config',
                 make_config([("irs", "scsi_rescan_maximal_timeout", "1")]))
    def testTimeout(self):
        with self.assertMaxDuration(1.2):
            iscsi.rescan()


class IscsiAdmTests(TestCaseBase):
    def testIfaceList(self):
        dirName = os.path.dirname(os.path.realpath(__file__))
        path = os.path.join(dirName, "iscsiadm_-m_iface.out")
        with open(path) as f:
            out = f.read().splitlines()

        Iface = iscsi.iscsiadm.Iface

        res = (Iface('default', 'tcp', None, None, None, None),
               Iface('iser', 'iser', None, None, None, None),
               Iface('eth1', 'tcp', None, None, 'SAN1', None),
               Iface('eth2', 'tcp', None, None, 'eth2', None))

        self.assertEqual(tuple(iscsi.iscsiadm.iface_list(out=out)), res)
