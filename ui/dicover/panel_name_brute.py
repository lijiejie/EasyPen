import wx
import time
import threading
import os
import sys
import glob
import queue
from lib.config import target_tree_list, root_path
import lib.config as conf
from lib.common import log_output, set_button_img, get_abs_path, edit_ports
from ui.log import show_update_log
from lib.process import do_masscan, do_nmap_scan, kill_child_processes
from lib.database import DBManager
from lib.jobs import BruteJob
from lib.event import LogEvent


def cal_width_for_linux(parent):
    text = wx.StaticText(parent, -1, "First Seen IP Only")
    if 'wxMSW' not in wx.PlatformInfo:
        width = text.GetBestSize()[0] + 50
    else:
        width = text.GetBestSize()[0] + 35
    text.Destroy()
    return width


class NameBrutePanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        # self.SetBackgroundColour(wx.WHITE)
        self.panel = parent
        width = cal_width_for_linux(self)
        lbl_enter_domain = wx.StaticText(self, -1, "Enter target domains to brute")
        font = lbl_enter_domain.GetFont()
        font.MakeBold()
        lbl_enter_domain.SetFont(font)
        self.txt_domain = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE, size=(300, 240))

        lbl_word_list = wx.StaticText(self, -1, "Word List", size=(90, -1), style=wx.ALIGN_CENTER)
        choices = ["Small DB (Fast)", "Full DB (Slow)"]
        self.cbo_brute_db = wx.ComboBox(self, -1, choices[0], size=(width, -1),
                                        choices=choices, style=wx.CB_DROPDOWN | wx.CB_READONLY)
        word_list_sizer = wx.BoxSizer(wx.HORIZONTAL)
        word_list_sizer.Add(lbl_word_list, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        word_list_sizer.Add(self.cbo_brute_db, 0, wx.ALL | wx.EXPAND, 2)

        lbl_process = wx.StaticText(self, -1, "Process Num", size=(90, -1), style=wx.ALIGN_CENTER)
        choices = [str(i) for i in range(1, 7)]
        self.cbo_process = wx.ComboBox(self, -1, choices[2], size=(width, -1),
                                       choices=choices, style=wx.CB_DROPDOWN | wx.CB_READONLY)
        process_sizer = wx.BoxSizer(wx.HORIZONTAL)
        process_sizer.Add(lbl_process, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        process_sizer.Add(self.cbo_process, 0, wx.ALL | wx.EXPAND, 2)

        self.chk_port_scan = wx.CheckBox(self, -1, "Port Scan", size=(-1, -1))
        self.chk_port_scan.Bind(wx.EVT_CHECKBOX, self.on_port_scan_check)
        choices = ["First Seen IP Only", "All IP"]
        self.cbo_ip_list = wx.ComboBox(self, -1, choices[0],
                                       choices=choices, style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(width, -1))
        self.cbo_ip_list.Enable(False)

        self.cbo_port_list = wx.ComboBox(self, -1, conf.port_choices[0],
                                         choices=conf.port_choices,
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(width, -1))
        self.cbo_port_list.Enable(False)

        port_scan_right_sizer = wx.BoxSizer(wx.VERTICAL)
        port_scan_right_sizer.Add(self.cbo_ip_list, 0, wx.ALL | wx.EXPAND, 2)
        port_scan_right_sizer.Add((-1, 5))
        port_scan_right_sizer.Add(self.cbo_port_list, 0, wx.ALL | wx.EXPAND, 2)

        btn_edit_port = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        btn_edit_port.SetToolTip("Edit ports profile")
        btn_edit_port.SetBackgroundColour(wx.WHITE)
        btn_edit_port.SetBitmap(wx.Image(get_abs_path('ui/resource/edit_ports.png')).ConvertToBitmap())
        btn_edit_port.Bind(wx.EVT_BUTTON, self.edit_port_profile)

        port_scan_sizer = wx.BoxSizer(wx.HORIZONTAL)
        port_scan_sizer.Add((5, -1), 1, wx.EXPAND)
        port_scan_sizer.Add(self.chk_port_scan, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 7)
        port_scan_sizer.Add(port_scan_right_sizer, 0, wx.ALL | wx.EXPAND, 2)
        port_scan_sizer.Add(btn_edit_port, 0, wx.ALIGN_BOTTOM | wx.BOTTOM, 2)

        self.chk_wildcard = wx.CheckBox(self, -1, "Force scan after wildcard test failed", size=(-1, -1))
        self.chk_disable_https = wx.CheckBox(self, -1, "Disable https cert scan to save time", size=(-1, -1))

        lbl_save_db = wx.StaticText(self, -1, "Save to DB", size=(90, -1), style=wx.ALIGN_CENTER)
        val = target_tree_list[0][0] if target_tree_list else ''
        self.db_choice = wx.ComboBox(self, -1, value=val, choices=[x[0] for x in target_tree_list],
                                     style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(width, -1))
        save_db_sizer = wx.BoxSizer(wx.HORIZONTAL)
        save_db_sizer.Add(lbl_save_db, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        save_db_sizer.Add(self.db_choice, 0, wx.ALL | wx.EXPAND, 2)

        right_sizer = wx.BoxSizer(wx.VERTICAL)
        right_sizer.Add((-1, 40 if 'wxMSW' in wx.PlatformInfo else 10))
        right_sizer.Add(word_list_sizer, 0, wx.ALL, 2)
        right_sizer.Add(process_sizer, 0, wx.ALL, 2)
        right_sizer.Add((-1, 20))
        right_sizer.Add(port_scan_sizer, 0, wx.ALL | wx.EXPAND, 2)
        right_sizer.Add((-1, 20))
        right_sizer.Add(self.chk_wildcard, 0, wx.LEFT, 15)
        right_sizer.Add((-1, 5))
        right_sizer.Add(self.chk_disable_https, 0, wx.LEFT, 15)
        right_sizer.Add((-1, 20))
        right_sizer.Add(save_db_sizer, 0, wx.ALL | wx.EXPAND, 2)

        self.btn_brute = wx.Button(self, -1, "Brute")
        self.btn_brute.SetBitmap(wx.Image(
            os.path.join(conf.root_path, 'ui/resource/brute_start.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_brute.SetBitmapMargins((2, 2))
        self.btn_brute.SetInitialSize()
        self.btn_brute.Bind(wx.EVT_BUTTON, self.brute_start)

        self.indicator = wx.ActivityIndicator(self)
        self.indicator.Hide()
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        button_sizer.Add(self.btn_brute, 0, wx.ALL, 2)
        button_sizer.Add((20, 20), 0, wx.ALL, 2)
        button_sizer.Add(self.indicator, 0, wx.LEFT | wx.TOP, 10)

        left_sizer = wx.BoxSizer(wx.VERTICAL)
        left_sizer.Add(lbl_enter_domain, 0, wx.TOP | wx.LEFT, 15)
        left_sizer.Add((5, 5), 0, wx.ALL, 2)
        left_sizer.Add(self.txt_domain, 0, wx.LEFT | wx.RIGHT | wx.EXPAND, 15)
        left_sizer.Add(button_sizer, 0, wx.ALL, 15)

        self.sizer = sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(left_sizer, 0, wx.LEFT, 25)
        sizer.Add(right_sizer, 0, wx.RIGHT, 15)
        self.SetSizer(sizer)

        self.job_list = []
        self.running_index = 0
        self.update_db_thread = None
        self.Bind(wx.EVT_END_PROCESS, self.on_process_ended)
        self.Bind(wx.EVT_IDLE, self.on_idle)
        self.brute_aborted = None
        self.update_db_index = 0
        self.port_scan_queue = queue.Queue()
        self.port_scan_result_queue = queue.Queue()
        self.port_scan_threads = []

    def edit_port_profile(self, event):
        edit_ports(self.cbo_port_list.GetValue())

    def on_port_scan_check(self, evt):
        self.cbo_ip_list.Enable(self.chk_port_scan.GetValue())
        self.cbo_port_list.Enable(self.chk_port_scan.GetValue())
        evt.Skip()

    def brute_stop(self):
        self.btn_brute.Enable(False)
        self.brute_aborted = True
        conf.name_brute_aborted = True
        log_output('Brute was aborted')
        conf.main_frame.statusBar.SetStatusText('Brute was aborted')

    def enable_input(self, status):
        self.txt_domain.Enable(status)
        self.cbo_brute_db.Enable(status)
        self.cbo_process.Enable(status)
        self.chk_port_scan.Enable(status)
        self.cbo_ip_list.Enable(status)
        self.cbo_port_list.Enable(status)
        self.db_choice.Enable(status)

    def brute_start(self, event):
        if self.btn_brute.GetLabel() == 'Stop':
            self.brute_stop()
            return

        self.brute_aborted = None
        conf.name_brute_aborted = False
        domains = self.txt_domain.GetValue().strip()
        if not domains or len(domains) < 4 or domains.count('.') == 0:
            wx.MessageDialog(self, 'Invalid Domain Input', 'Names Brute', wx.ICON_WARNING).ShowModal()
            return

        brute_db = self.cbo_brute_db.GetValue()
        full_db = " --full " if brute_db.find('Full DB') >= 0 else ""
        process_num = self.cbo_process.GetValue()
        wildcard = " --wildcard " if self.chk_wildcard.GetValue() else ""
        disable_cert_scan = " --no-https " if self.chk_disable_https.GetValue() else ""

        selected_db = self.db_choice.GetValue()
        if not selected_db or not os.path.exists(os.path.join(root_path, 'database/' + selected_db)):
            wx.MessageDialog(self, 'Target database not found', 'Names Brute', wx.ICON_WARNING).ShowModal()
            return

        self.enable_input(False)
        self.btn_brute.SetLabel('Stop')
        set_button_img(self.btn_brute, get_abs_path('ui/resource/brute_stop.png'))

        self.indicator.Show()
        self.sizer.Layout()
        self.indicator.Start()
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(start_timer=True, interval=300))
        cmd = sys.executable + " " + os.path.join(root_path, "tools/subDomainsBrute/subDomainsBrute.py")
        if conf.is_windows_exe:
            cmd = os.path.join(conf.root_path, "tools/subDomainsBrute/subDomainsBrute.exe ")
        cmd += full_db
        cmd += ' -p ' + process_num + ' '
        cmd += wildcard
        cmd += disable_cert_scan
        self.job_list = []
        for domain in domains.split():
            if not domain.strip() or len(domain.strip()) <= 3:
                log_output('Invalid domain: %s' % domain.strip())
                continue
            job = BruteJob(self, domain, cmd)
            self.job_list.append(job)

        self.running_index = 0
        self.update_db_index = 0
        self.update_db_thread = threading.Thread(target=self.brute_update_db)
        self.update_db_thread.start()

        self.job_list[0].start()

    def brute_finished(self):
        self.enable_input(True)
        self.btn_brute.SetLabel('Brute')
        self.btn_brute.Enable(True)
        set_button_img(self.btn_brute, get_abs_path('ui/resource/brute_start.png'))
        self.indicator.Hide()
        self.sizer.Layout()
        self.indicator.Stop()
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(stop_timeer=True))

    def brute_update_db(self):
        self.port_scan_threads = []
        db_manager = DBManager(db_name=self.db_choice.GetValue())
        # port scan config
        port_scan_enabled = self.chk_port_scan.GetValue()
        if port_scan_enabled:
            self.port_scan_thread_status = [0 for x in range(conf.max_num_of_scan_process)]
            for index in range(conf.max_num_of_scan_process):
                t = threading.Thread(target=self.port_scan_thread, args=(index,))
                self.port_scan_threads.append(t)
                t.start()
        else:
            self.port_scan_thread_status = []

        first_seen_ip_only = self.cbo_ip_list.GetValue() == "First Seen IP Only"

        while not conf.end_me:
            if self.brute_aborted:
                db_manager.close_db()
                process = self.job_list[self.running_index].process
                if process:
                    if conf.is_windows_exe:
                        kill_child_processes(process.GetPid())
                    wx.Kill(process.GetPid(), wx.SIGKILL)
                self.update_db_thread = None
                self.brute_finished()
                return

            lines_to_process = self.find_unprocessed_lines()
            if lines_to_process:
                domain_insert_count = domain_update_count = ip_insert_count = 0
                port_scan_ip_set = set([])
                for line in lines_to_process:
                    line = line.strip()
                    if not line:
                        continue
                    ret = line.split('\t')
                    if len(ret) != 2:
                        continue
                    domain = ret[0].strip()
                    ips = ret[1].strip().split(',')

                    domain_id, insert_count, update_count = db_manager.insert_or_update_domain(domain)
                    domain_update_count += update_count
                    domain_insert_count += insert_count

                    for ip in ips:
                        ip = ip.strip()
                        ip_id, insert_count = db_manager.insert_or_update_ip(ip, domain_id)
                        if insert_count == 1:
                            port_scan_ip_set.add(ip)
                        else:
                            # ip existed in db
                            if not first_seen_ip_only:
                                port_scan_ip_set.add(ip)

                show_update_log(domain_insert_count=domain_insert_count, domain_update_count=domain_update_count,
                                ip_insert_count=ip_insert_count, refresh=self.db_choice.GetValue())

                if not self.brute_aborted and port_scan_enabled and port_scan_ip_set:
                    self.port_scan_queue.put(port_scan_ip_set)

            port_insert_count = port_update_count = 0
            while self.port_scan_result_queue.qsize() > 0:
                hosts = self.port_scan_result_queue.get()
                for h in hosts:
                    if not h.host_on:
                        continue
                    ip_id = db_manager.get_ip_id(h.ipv4_addr)
                    for p in h.ports:
                        service_version = p['service_product'] + ' ' + p['service_version']
                        insert_count, update_count = db_manager.insert_or_update_port(
                            p['port_id'], ip_id, p['service_name'], service_version, p['is_http']
                        )
                        port_update_count += update_count
                        port_insert_count += insert_count

            show_update_log(port_insert_count=port_insert_count, port_update_count=port_update_count,
                            refresh=self.db_choice.GetValue())

            if all([j.update_db_ok for j in self.job_list]):
                if self.port_scan_result_queue.qsize() == 0 and self.port_scan_queue.qsize() == 0 and \
                        not any(self.port_scan_thread_status):
                    db_manager.close_db()
                    self.update_db_thread = None
                    self.brute_finished()
                    break
            else:
                time.sleep(0.3)

    def port_scan_thread(self, index):
        ports_to_scan = conf.ports_dict[self.cbo_port_list.GetValue().replace(' ', '_')]
        while not conf.end_me and self.update_db_thread is not None:
            try:
                port_scan_ip_set = self.port_scan_queue.get(timeout=1.0)
                self.port_scan_thread_status[index] = 1   # thread busy, write db thread should wait
            except queue.Empty as e:
                self.port_scan_thread_status[index] = 0   # this thread is free now
                continue
            # to ensure thread safe
            # use PostEvent instead of directly use wx.LogMessage in a separate thread
            wx.PostEvent(conf.main_frame.target_tree,
                         LogEvent(msg='Init port scan for %s IP' % len(port_scan_ip_set)))
            try:
                masscan_result = do_masscan(port_scan_ip_set, ports_to_scan, source='name_brute')
                for port in masscan_result:
                    if self.brute_aborted:    # user abort
                        break
                    ips = [_ip for _ip in masscan_result[port]]
                    hosts = do_nmap_scan(port, ips, source='name_brute')
                    self.port_scan_result_queue.put(hosts)

            except Exception as e:
                wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='port_scan_thread.exception: %s' % str(e)))

    def find_unprocessed_lines(self):
        try:
            if self.update_db_index >= len(self.job_list):
                return []
        except Exception as e:
            return []
        lines_to_return = []
        job = self.job_list[self.update_db_index]
        if job.status == 'finished':
            full_file_path = 'tools/subDomainsBrute/%s' % job.output_file
            if not os.path.exists(full_file_path):
                job.update_db_ok = True
                self.update_db_index += 1
            else:
                time.sleep(0.1)    # in case not flushed yet
                with open(full_file_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in job.processed_lines:
                            job.processed_lines.append(line)
                            lines_to_return.append(line)
                if not lines_to_return:    # Process end and all lines processed already
                    job.update_db_ok = True
                    self.update_db_index += 1
                try:
                    os.remove(full_file_path)
                except Exception as e:
                    pass
        else:
            for tmp_file in glob.glob(os.path.join(job.tmp_dir, '*.txt')):
                with open(tmp_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and line not in job.processed_lines:
                            job.processed_lines.append(line)
                            lines_to_return.append(line)
        return lines_to_return

    def on_process_ended(self, evt):
        if evt.Pid in [j.pid for j in self.job_list]:
            if evt.ExitCode != 0:
                log_output('Domain brute process end with [error code %s], pid: %s' % (evt.ExitCode, evt.Pid))

                import importlib
                for package in ['aiodns', 'async_timeout']:
                    if not importlib.util.find_spec(package):
                        log_output("[ERROR] Package %s is missing, run: pip install %s" % (package, package))
            else:
                log_output('Domain brute process end, pid: %s' % evt.Pid)

            cur_job = self.job_list[self.running_index]
            cur_job.status = 'finished'
            cur_job.process.Destroy()
            cur_job.process = None
            if self.brute_aborted:
                return
            if self.running_index < len(self.job_list) - 1:
                self.running_index += 1
                next_job = self.job_list[self.running_index]
                next_job.start()
            else:
                if not self.update_db_thread:
                    self.brute_finished()

    def on_idle(self, evt):
        if self.job_list:
            job = self.job_list[self.running_index]
            if job.process:
                stream = job.process.GetInputStream()
                if stream.CanRead():
                    text = stream.read().strip()
                    conf.main_frame.statusBar.SetStatusText(text)
        evt.Skip()


if __name__ == '__main__':

    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(710, 429))
    panel = NameBrutePanel(frame)
    panel.db_choice.Append(['default'])
    panel.db_choice.SetValue('default')
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
