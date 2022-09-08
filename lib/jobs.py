import wx
import time
from lib.common import get_output_tmp_path, log_output


class BruteJob(object):
    def __init__(self, parent, domain, cmd_prefix):
        self.parent = parent
        self.domain = domain.strip()
        self.cmd_prefix = cmd_prefix
        self.output_file = ''
        self.tmp_dir = ''
        self.process = None
        self.pid = None
        self.status = ''    # running / finished
        self.processed_lines = []
        self.update_db_ok = False

    def start(self):
        self.process = wx.Process(self.parent)
        self.process.Redirect()
        self.output_file = get_output_tmp_path('%s_%s.txt' % (self.domain, str(int(time.time()))))
        self.tmp_dir = get_output_tmp_path('%s_%s' % (self.domain, str(int(time.time()))))
        cmd = self.cmd_prefix + ' -o ' + self.output_file + ' '
        cmd += '--tmp ' + self.tmp_dir + ' '
        self.pid = wx.Execute(cmd + self.domain, wx.EXEC_ASYNC, self.process)
        log_output('Brute domain: %s, pid: %s' % (self.domain, self.pid))
