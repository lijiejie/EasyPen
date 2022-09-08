import wx
import os
import sys
import webbrowser
import subprocess
import re
import time
import glob
import threading
import wx.lib.newevent
from lib.common import set_button_img, log_output
import lib.config as conf
from lib.jobs import BruteJob


BruteToolEvent, Domain_Brute_Event_BINDER = wx.lib.newevent.NewEvent()


class SubDomainsBrutePanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        self.SetBackgroundColour(wx.WHITE)

        label = wx.StaticText(self, -1, 'Domain')
        self.txt_domain = wx.TextCtrl(self, -1, size=(200, -1))
        self.txt_domain.SetValue('')
        label_profile = wx.StaticText(self, -1, 'Profile')
        choices = ["SmallDB (1 process)", "SmallDB (2 process)", "SmallDB (4 process)",
                   "FullDB (2 process)", "FullDB (4 process)", "FullDB (6 process)"]
        self.cbo_brute_db = wx.ComboBox(self, -1, "SmallDB (2 process)", size=(200, -1),
                                        choices=choices, style=wx.CB_DROPDOWN | wx.CB_READONLY)

        self.btn_brute = btn_brute = wx.Button(self, -1, "Brute")
        btn_brute.Bind(wx.EVT_BUTTON, self.brute_start)
        self.Bind(wx.EVT_END_PROCESS, self.on_process_ended)
        self.indicator = wx.ActivityIndicator(self)
        self.indicator.Hide()
        set_button_img(btn_brute, os.path.join(conf.root_path, 'ui/resource/brute_start.png'))
        sizer_left_up = wx.BoxSizer(wx.HORIZONTAL)
        sizer_left_up.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_left_up.Add((10, 20))
        sizer_left_up.Add(self.txt_domain, 0, wx.ALIGN_CENTER_VERTICAL)

        sizer_left_down = wx.BoxSizer(wx.HORIZONTAL)
        sizer_left_down.Add(label_profile, 0, wx.ALIGN_CENTER_VERTICAL)
        sizer_left_down.Add((20, 20))
        sizer_left_down.Add(self.cbo_brute_db, 0, wx.ALIGN_CENTER_VERTICAL)

        sizer_left = wx.BoxSizer(wx.VERTICAL)
        sizer_left.Add(sizer_left_up, 0, wx.TOP, 10)
        sizer_left.Add((-1, 10))
        sizer_left.Add(sizer_left_down, 0)

        sizer_up = wx.BoxSizer(wx.HORIZONTAL)
        sizer_up.Add(sizer_left, 0)
        sizer_up.Add((30, -1))
        sizer_up.Add(btn_brute, 0, wx.ALIGN_BOTTOM)
        sizer_up.Add((20, -1))
        sizer_up.Add(self.indicator, 0, wx.ALIGN_BOTTOM | wx.BOTTOM, 10)

        self.result = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(-1, -1))
        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(sizer_up, 0, wx.ALL, 10)
        sizer_main.Add(self.result, 1, wx.ALL | wx.EXPAND, 10)

        lbl_url = wx.StaticText(self, -1, 'Docs: https://github.com/lijiejie/subDomainsBrute')
        font = lbl_url.GetFont()
        font.MakeBold()
        lbl_url.SetFont(font)
        lbl_url.SetForegroundColour((72, 118, 255))
        lbl_url.SetCursor(wx.Cursor(wx.CURSOR_HAND))
        lbl_url.Bind(wx.EVT_LEFT_DOWN, self.url_click)
        self.btn_view_files = btn_view_files = wx.Button(self, -1, "View File")
        btn_view_files.Enable(False)
        btn_view_files.Bind(wx.EVT_BUTTON, self.view_files)
        sizer_down = wx.BoxSizer(wx.HORIZONTAL)
        sizer_down.Add(lbl_url, 0, wx.TOP, 14)
        sizer_down.AddStretchSpacer(1)
        sizer_down.Add(btn_view_files, 0, wx.ALL, 10)

        sizer_main.Add(sizer_down, 0, wx.ALL | wx.EXPAND, 10)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add((20, -1))
        sizer.Add(sizer_main, 1, wx.EXPAND)
        sizer.Add((20, -1))
        self.SetSizer(sizer)
        self.Fit()
        self.brute_aborted = None
        self.job = None
        self.Bind(wx.EVT_IDLE, self.on_idle)
        self.Bind(Domain_Brute_Event_BINDER, self.process_my_event)

    def process_my_event(self, event):
        if event.domains:
            for domain in event.domains:
                self.result.AppendText(domain + '\n')

    def brute_start(self, event):
        if self.btn_brute.GetLabel() == 'Stop':
            self.brute_stop()
            return

        domain = self.txt_domain.GetValue().strip()
        if not domain or len(domain) < 4 or domain.count('.') == 0:
            wx.MessageDialog(self, 'Invalid Domain Input', 'Names Brute', wx.ICON_WARNING).ShowModal()
            return

        brute_config = self.cbo_brute_db.GetValue()
        full_db = " --full " if brute_config.find('FullDB') >= 0 else ""
        process_num = re.search(r'\d', brute_config).group()

        self.enable_input(False)
        self.btn_brute.SetLabel('Stop')
        self.result.Clear()
        set_button_img(self.btn_brute, os.path.join(conf.root_path, 'ui/resource/brute_stop.png'))
        self.indicator.Show()
        self.Layout()
        self.indicator.Start()

        self.brute_aborted = None
        self.domain = self.txt_domain.GetValue().strip()
        self.txt_domain.Enable(False)
        cmd = sys.executable + " " + os.path.join(conf.root_path, "tools/subDomainsBrute/subDomainsBrute.py")
        if conf.is_windows_exe:
            cmd = os.path.join(conf.root_path, "tools/subDomainsBrute/subDomainsBrute.exe ")
        cmd += full_db
        cmd += ' -p ' + process_num + ' '
        self.job = BruteJob(self, domain, cmd)
        self.update_db_thread = threading.Thread(target=self.brute_update_db)
        self.update_db_thread.start()
        self.job.start()
        self.output_full_path = self.job.output_file

    def brute_finished(self):
        self.enable_input(True)
        self.btn_brute.SetLabel('Brute')
        self.btn_brute.Enable(True)
        set_button_img(self.btn_brute, os.path.join(conf.root_path, 'ui/resource/brute_start.png'))
        self.indicator.Hide()
        self.Layout()
        self.indicator.Stop()
        self.job = None

    def brute_stop(self):
        self.btn_brute.Enable(False)
        self.brute_aborted = True
        log_output('Sub domain brute was aborted')
        if conf.main_frame:
            conf.main_frame.statusBar.SetStatusText('Sub domain brute was aborted')

    def enable_input(self, status):
        self.txt_domain.Enable(status)
        self.cbo_brute_db.Enable(status)

    def brute_update_db(self):
        while not conf.end_me:
            if self.brute_aborted:
                if self.job.process:
                    wx.Kill(self.job.process.GetPid(), wx.SIGKILL)
                self.update_db_thread = None
                self.brute_finished()
                return

            lines_to_process = self.find_unprocessed_lines()
            if lines_to_process:
                wx.PostEvent(self, BruteToolEvent(domains=lines_to_process))
            if self.job.update_db_ok:
                self.update_db_thread = None
                self.brute_finished()
                break
            else:
                time.sleep(0.3)

    def find_unprocessed_lines(self):
        lines_to_return = []
        job = self.job
        if not job.tmp_dir:
            return []
        if job.status == 'finished':
            if not os.path.exists(self.output_full_path):
                job.update_db_ok = True
            else:
                time.sleep(0.1)    # in case not flushed yet
                with open(self.output_full_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in job.processed_lines:
                            job.processed_lines.append(line)
                            lines_to_return.append(line)
                if not lines_to_return:    # Process end and all lines processed already
                    job.update_db_ok = True
        else:
            for tmp_file in glob.glob(os.path.join(job.tmp_dir, '*.txt')):
                with open(tmp_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in job.processed_lines:
                            job.processed_lines.append(line)
                            lines_to_return.append(line)
        return lines_to_return

    def on_idle(self, evt):
        if self.job and self.job.process:
            stream = self.job.process.GetInputStream()
            if stream.CanRead():
                text = stream.read()
                if conf.main_frame:
                    conf.main_frame.statusBar.SetStatusText(text)
                else:
                    print(text)

    def on_process_ended(self, evt):
        if evt.ExitCode != 0:
            log_output('Domain brute process end with [error code %s], pid: %s' % (evt.ExitCode, evt.Pid))
            import importlib
            for package in ['aiodns', 'async_timeout']:
                if not importlib.util.find_spec(package):
                    log_output("[ERROR] Package %s is missing, run: pip install %s" % (package, package))
        else:
            log_output('Domain brute process end, pid: %s' % evt.Pid)

        self.job.status = 'finished'
        self.job.process.Destroy()
        self.job.process = None
        if self.brute_aborted:
            return

        if not self.update_db_thread:
            self.brute_finished()

        self.result.AppendText('\nProcess Exited.  Domains saved to\n' + self.output_full_path)
        self.txt_domain.Enable(True)
        if os.path.exists(self.output_full_path):
            self.btn_view_files.Enable(True)
        self.btn_brute.Enable(True)

    def url_click(self, event):
        webbrowser.open_new_tab('https://github.com/lijiejie/subDomainsBrute')
        event.Skip()

    def view_files(self, event):
        if os.path.exists(self.output_full_path):
            self.btn_view_files.Enable(False)
            folder = os.path.dirname(self.output_full_path)
            try:
                if sys.platform == 'win32':
                    subprocess.Popen(r'explorer /select,"%s"' % self.output_full_path)
                elif sys.platform == 'darwin':
                    subprocess.Popen(['open', folder])
                else:
                    subprocess.Popen(['xdg-open', folder])
            except Exception as e:
                pass
            self.btn_view_files.Enable(True)


if __name__ == '__main__':
    wx.LogMessage = print
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    panel = wx.Panel(frame, -1)
    panel_git_hack = SubDomainsBrutePanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()

