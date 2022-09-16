import time
import wx
import os
import threading
import copy
import dns.resolver
import queue
import json
from urllib.parse import urlparse
import wx.lib.newevent
from lib.config import target_tree_list
from lib.database import DBManager
from lib.common import is_ip_addr, get_hostname_port_mask, edit_ports, log_output
from lib.ip_set_store import IPSetStore
import lib.config as conf
from lib.common import set_button_img, get_abs_path, count_num_of_ips
from ui.log import show_update_log
from lib.event import LogEvent, StatusEvent
from lib.process import do_masscan, do_nmap_scan
from ui.scan.poc_runner import scan_main


ScanEndedEvent, SCAN_ENDED_EVT_BINDER = wx.lib.newevent.NewEvent()


class HostsFileDropTarget(wx.FileDropTarget):
    def __init__(self, panel):
        wx.FileDropTarget.__init__(self)
        self.panel = panel

    def OnDropFiles(self, x, y, filenames):
        out = ''
        for _name in filenames:
            out += os.path.basename(_name) + '\n'
        # wx.LogMessage('About to import targets from file:\n' + out)
        self.panel.files_to_import = filenames
        self.panel.txt_targets.SetValue(
            'Import targets from %s files\nDouble click to clear\n\n' % len(filenames) + out)
        self.panel.txt_targets.SetEditable(False)
        return True


class VulnerabilityScanBox(wx.StaticBox):
    def __init__(self, parent):
        wx.StaticBox.__init__(self, parent, -1, "", size=(-1, -1))
        self.panel = parent
        self.frame = parent.frame
        self.sizer = sizer = wx.StaticBoxSizer(self, wx.HORIZONTAL)

        self.txt_targets = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE, size=(-1, 110))
        file_drop_targets = HostsFileDropTarget(self)
        self.files_to_import = None
        self.txt_targets.SetDropTarget(file_drop_targets)
        self.txt_targets.Bind(wx.EVT_LEFT_DCLICK, self.clear_imported_file)

        btn_help = wx.Button(self, -1, "", size=(30, 30), style=wx.NO_BORDER)
        btn_help.SetBitmap(wx.Image(get_abs_path('ui/resource/btn_help.png')).ConvertToBitmap(), wx.TOP)
        btn_help.SetBitmapMargins((2, 2))
        btn_help.Bind(wx.EVT_BUTTON, self.show_targets_help)
        self.btn_open_file = wx.Button(self, -1, "", size=(30, 30), style=wx.NO_BORDER)
        self.btn_open_file.SetBitmap(
            wx.Image(get_abs_path('ui/resource/import_targets_16.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_open_file.SetBitmapMargins((2, 2))
        self.btn_open_file.Bind(wx.EVT_BUTTON, self.import_targets)
        right_up_sizer_1 = wx.BoxSizer(wx.VERTICAL)
        right_up_sizer_1.Add(btn_help, 0, wx.ALL, 2)
        right_up_sizer_1.Add((-1, 15))
        right_up_sizer_1.Add(self.btn_open_file, 0, wx.ALL | wx.EXPAND, 2)

        self.chk_port_scan = wx.CheckBox(self, -1, "PortScan", size=(70, -1))
        self.chk_port_scan.Bind(wx.EVT_CHECKBOX, self.on_port_scan_check)
        lbl_save_db = wx.StaticText(self, -1, "Save to DB", size=(70, -1))
        val = target_tree_list[0][0] if target_tree_list else ''
        self.db_choice = wx.ComboBox(self, -1, value=val, choices=[x[0] for x in target_tree_list],
                                     style=wx.CB_DROPDOWN | wx.CB_READONLY)
        right_up_sizer_2 = wx.BoxSizer(wx.VERTICAL)
        right_up_sizer_2.Add(self.chk_port_scan, 0, wx.TOP | wx.DOWN | wx.LEFT, 10)
        right_up_sizer_2.Add((-1, 10))
        right_up_sizer_2.Add(lbl_save_db, 0, wx.ALL, 8)

        self.cbo_port_list = wx.ComboBox(self, -1, conf.port_choices[0], choices=conf.port_choices,
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.cbo_port_list.Enable(False)
        right_up_sizer_3 = wx.BoxSizer(wx.VERTICAL)
        right_up_sizer_3.Add(self.cbo_port_list, 0, wx.ALL | wx.EXPAND, 5)
        right_up_sizer_3.Add((-1, 10))
        right_up_sizer_3.Add(self.db_choice, 0, wx.ALL | wx.EXPAND, 5)

        btn_edit_port = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        btn_edit_port.SetToolTip("Edit ports profile")
        btn_edit_port.SetBackgroundColour(wx.WHITE)
        btn_edit_port.SetBitmap(wx.Image(get_abs_path('ui/resource/edit_ports.png')).ConvertToBitmap())
        btn_edit_port.Bind(wx.EVT_BUTTON, self.edit_port_profile)

        right_up_sizer = wx.BoxSizer(wx.HORIZONTAL)
        right_up_sizer.Add(right_up_sizer_1, 0, wx.ALL, 2)
        right_up_sizer.Add((20, -1))
        right_up_sizer.Add(right_up_sizer_2, 0, wx.ALL | wx.EXPAND, 2)
        right_up_sizer.Add(right_up_sizer_3, 1, wx.ALL | wx.EXPAND, 2)
        right_up_sizer.Add(btn_edit_port, 0, wx.ALL | wx.ALIGN_TOP, 5)

        self.btn_scan = wx.Button(self, -1, "Scan")
        self.btn_scan.SetBitmap(wx.Image(get_abs_path('ui/resource/portscan_start.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_scan.SetBitmapMargins((2, 2))
        self.btn_scan.SetInitialSize()
        self.btn_scan.Bind(wx.EVT_BUTTON, self.vulnerability_scan_start)
        self.indicator = wx.ActivityIndicator(self)
        self.indicator.Hide()
        right_down_sizer = wx.BoxSizer(wx.HORIZONTAL)
        right_down_sizer.Add(self.btn_scan, 0, wx.ALL, 5)
        right_down_sizer.Add(self.indicator, 0, wx.ALL | wx.EXPAND, 15)

        right_sizer = wx.BoxSizer(wx.VERTICAL)
        right_sizer.Add(right_up_sizer, 0)
        right_sizer.Add(right_down_sizer, 0, wx.TOP, 5)

        sizer.Add(self.txt_targets, 1, wx.EXPAND | wx.ALL, 5)
        sizer.Add(right_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 5)
        self.scan_aborted = None
        self.sync_db_thread_exit = False
        self.port_scan_queue = queue.Queue()
        self.port_scan_result_queue = queue.Queue()
        self.port_scan_threads = []
        self.port_scan_thread_status = None
        self.port_scan_tasks_all_entered_queue = None
        self.Bind(SCAN_ENDED_EVT_BINDER, self.scan_end)

    def edit_port_profile(self, event):
        edit_ports(self.cbo_port_list.GetValue())

    def show_targets_help(self, event):
        dlg = wx.MessageDialog(self, conf.supported_inputs, 'Target Input', wx.OK | wx.ICON_INFORMATION)
        dlg.ShowModal()
        dlg.Destroy()

    def on_port_scan_check(self, evt):
        self.cbo_port_list.Enable(self.chk_port_scan.GetValue())
        evt.Skip()

    def clear_imported_file(self, event):
        if self.files_to_import:
            self.files_to_import = None
            self.txt_targets.SetValue('')
            self.txt_targets.SetEditable(True)

    def import_targets(self, event):
        dlg = wx.FileDialog(self, message="Import targets from file", defaultDir=conf.root_path, defaultFile="",
                            wildcard="All Files (*.*)|*.*",
                            style=wx.FD_OPEN | wx.FD_MULTIPLE | wx.FD_FILE_MUST_EXIST | wx.FD_PREVIEW
                            )
        if dlg.ShowModal() == wx.ID_OK:
            paths = dlg.GetPaths()
            if len(paths) == 1:   # only one file selected
                path = paths[0]
                if os.path.getsize(path) < 100 * 1024:
                    with open(path) as f:
                        self.txt_targets.SetValue(f.read())
                else:
                    self.files_to_import = paths
                    self.txt_targets.SetValue('No preview on large file\n'
                                              'targets will be imported from\n\n' + os.path.basename(path) +
                                              '\n\nDouble click to remove it')
                    self.txt_targets.SetEditable(False)
            else:
                self.files_to_import = paths
                out = ''
                for _name in paths:
                    out += os.path.basename(_name) + '\n'
                self.txt_targets.SetValue('Import targets from %s files\nDouble click to clear\n\n' % len(paths) + out)
                self.txt_targets.SetEditable(False)
        dlg.Destroy()

    def vulnerability_scan_start(self, event):
        if self.btn_scan.GetLabel() == 'Stop':
            self.scan_aborted = True
            conf.scan_aborted = True   # notify poc_runner to clear task queue and exit
            self.btn_scan.Enable(False)
            log_output('Scan was aborted, wait a few seconds...')
            self.frame.statusBar.SetStatusText('Scan was aborted')
            while self.port_scan_queue.qsize() > 0:    # empty the scan queue for later reuse
                try:
                    self.port_scan_queue.get_nowait()
                except Exception as e:
                    pass
            return

        if not self.files_to_import and len(self.txt_targets.GetValue()) < 4:
            wx.MessageDialog(self, 'No targets input', 'Scanner', wx.ICON_WARNING).ShowModal()
            return

        selected_db = self.db_choice.GetValue()
        if not selected_db or not os.path.exists(os.path.join(conf.root_path, 'database/' + selected_db)):
            wx.MessageDialog(self, 'Target database not found', 'Scanner', wx.ICON_WARNING).ShowModal()
            return

        # get selected plugins
        num_of_scripts = self.panel.scripts_panel.get_checked_items()
        if conf.user_selected_plugins is None:
            wx.MessageDialog(self, 'No scripts were checked, \nshould at least check one',
                             'Scanner', wx.ICON_WARNING).ShowModal()
            return

        log_output('Vulnerability scan start, with %s plugins enabled' % num_of_scripts)

        # clear result panel
        self.panel.notebook.SetSelection(1)
        self.panel.result_panel.list.ClearAll()
        self.panel.result_panel.itemDataMap = {}
        self.panel.result_panel.populate_list()

        self.scan_aborted = False
        conf.scan_aborted = False
        self.enable_input(False)
        self.btn_scan.SetLabel('Stop')
        set_button_img(self.btn_scan, 'ui/resource/brute_stop.png')
        self.indicator.Show()
        self.panel.sizer.Layout()
        self.indicator.Start()
        self.panel.notebook.SetPageText(1, "  Results  ")
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(start_timer=True, interval=100))
        threading.Thread(target=self.do_vulnerability_scan).start()

    def enable_input(self, status):
        self.txt_targets.Enable(status)
        self.btn_open_file.Enable(status)
        self.chk_port_scan.Enable(status)
        self.cbo_port_list.Enable(status)
        self.db_choice.Enable(status)

    def ensure_queue_cleared(self):
        # aborted task may cause scan queue still remain tasks
        while self.port_scan_queue.qsize() > 0:
            try:
                self.port_scan_queue.get_nowait()
            except Exception as e:
                pass
        while self.port_scan_result_queue.qsize() > 0:
            try:
                self.port_scan_result_queue.get_nowait()
            except Exception as e:
                pass

    def scan_end(self, event):
        self.enable_input(True)
        self.btn_scan.SetLabel('Scan')
        self.btn_scan.Enable(True)
        set_button_img(self.btn_scan, 'ui/resource/portscan_start.png')
        self.indicator.Hide()
        self.panel.sizer.Layout()
        self.indicator.Stop()
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(stop_timeer=True))

    def do_vulnerability_scan(self):
        conf.port_scan_finished = False
        conf.scanner_completed = False
        threading.Thread(target=scan_main).start()
        self.port_scan_thread_status = [1 for _ in range(conf.max_num_of_scan_process)]
        for index in range(conf.max_num_of_scan_process):
            t = threading.Thread(target=self.port_scan_thread, args=(index,))
            self.port_scan_threads.append(t)
            t.start()
        self.sync_db_thread_exit = False
        threading.Thread(target=self.sync_db_thread).start()
        self.port_scan_tasks_all_entered_queue = False
        if not self.files_to_import:
            # input from textbox
            self.process_host_scan(self.txt_targets.GetValue())
        else:
            for path in self.files_to_import:
                if self.scan_aborted:    # abort scan, skip rest files
                    continue
                if os.path.getsize(path) > 10 * 1024 * 1024:    # 10MB
                    wx.PostEvent(self.frame.target_tree, LogEvent(msg="File size too large, ignored: %s" % path))
                    continue
                wx.PostEvent(self.frame.target_tree, LogEvent(msg='Import targets from: %s' % path))
                with open(path) as f:
                    self.process_host_scan(f.read())
        self.port_scan_tasks_all_entered_queue = True
        while not self.port_scan_finished() and not self.scan_aborted and not conf.end_me:
            time.sleep(0.1)
        conf.port_scan_finished = True
        while not self.sync_db_thread_exit:
            time.sleep(0.1)
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='Port scan finished.'))
        while not conf.scanner_completed:
            time.sleep(0.3)
        wx.PostEvent(self.frame.target_tree, LogEvent(msg='Vulnerability scan finished.'))
        self.ensure_queue_cleared()
        # this is important, do not update GUI in this thread
        wx.PostEvent(self, ScanEndedEvent())

    def sync_db_thread(self):
        db_manager = DBManager(self.db_choice.GetValue())
        while not self.port_scan_finished() and not self.scan_aborted and not conf.end_me:
            try:
                r_type, result = self.port_scan_result_queue.get(timeout=0.5)
            except Exception as e:
                continue
            if r_type == 'ping_scan':
                try:
                    for alive_ip in result[0]:
                        db_manager.insert_or_update_ip(alive_ip)
                    wx.PostEvent(conf.main_frame.target_tree,
                                 LogEvent(msg='Active hosts found: %s' % len(result[0]),
                                          refresh=self.db_choice.GetValue()))
                except Exception as e:
                    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='do_ping_scan.exception: %s' % str(e)))
            elif r_type == 'port_scan':
                port_insert_count = port_update_count = 0
                try:
                    for h in result:
                        if not h.host_on:
                            continue
                        ip_id, _ = db_manager.insert_or_update_ip(h.ipv4_addr)
                        for p in h.ports:
                            service_version = p['service_product'] + ' ' + p['service_version']
                            insert_count, update_count = db_manager.insert_or_update_port(
                                p['port_id'], ip_id, p['service_name'], service_version, p['is_http']
                            )
                            port_update_count += update_count
                            port_insert_count += insert_count
                            msg = {'ip': h.ipv4_addr, 'port': p['port_id'], 'service': p['service_name'],
                                   'is_http': p['is_http'], 'policy_name': '',
                                   'plugin_list': conf.user_selected_plugins}
                            conf.loop.call_soon_threadsafe(conf.task_queue.put_nowait, json.dumps(msg))
                            conf.loop.call_soon_threadsafe(
                                conf.weak_pass_brute_task_queue.put_nowait, json.dumps(msg))
                except Exception as e:
                    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='do_port_scan.exception: %s' % str(e)))

                show_update_log(port_insert_count=port_insert_count, port_update_count=port_update_count,
                                refresh=self.db_choice.GetValue())
        db_manager.close_db()
        self.sync_db_thread_exit = True

    def process_host_scan(self, text):
        """
        this function is a bit complex,
        because we have to process different kinds of user input
        domain / ip / url, with or without ports
        """
        hosts = set([])
        status_bar_counter = 0
        for line in text.strip().split('\n'):
            if not line.strip():
                continue
            item = line.strip().split()[0]
            if item:
                _ = urlparse(item, 'http')
                if _.scheme and _.netloc:
                    is_http = None
                    if _.scheme.startswith('http'):
                        is_http = True
                    ip = port = None
                    if _.netloc.count(':') == 1:
                        ip, port = _.netloc.split(':')
                    else:
                        ip = _.netloc

                    msg = {'ip': ip, 'port': port, 'service': _.scheme,
                           'is_http': is_http, 'policy_name': '', 'plugin_list': conf.user_selected_plugins}
                    status_bar_counter += 1
                    if status_bar_counter % 200 == 1:   # show first 1 of every 200
                        wx.PostEvent(conf.main_frame, StatusEvent(text='Add task %s:%s' % (ip, port)))
                    conf.loop.call_soon_threadsafe(conf.task_queue.put_nowait, json.dumps(msg))
                    conf.loop.call_soon_threadsafe(
                        conf.weak_pass_brute_task_queue.put_nowait, json.dumps(msg))
                else:
                    hosts.add(item)

        # resolve domain
        domain_insert_count = domain_update_count = ip_insert_count = 0
        resolver = dns.resolver.Resolver()
        hosts_grouped_by_port = {}    # grouped by a single port, user specified port must be scanned first
        db_manager = DBManager(self.db_choice.GetValue())
        for item in copy.deepcopy(hosts):
            if self.scan_aborted:    # abort check
                return
            hostname, port, mask = get_hostname_port_mask(item)
            if port and port not in hosts_grouped_by_port:
                hosts_grouped_by_port[port] = set([])
            if is_ip_addr(hostname):
                if port:
                    if mask is None:
                        hosts_grouped_by_port[port].add(hostname)   # A single IP
                    else:
                        hosts_grouped_by_port[port].add('%s/%s' % (hostname, mask))    # IP/Mask
            else:
                hosts.remove(item)
                try:
                    answers = resolver.resolve(hostname)
                    domain_id, insert_count, update_count = db_manager.insert_or_update_domain(hostname)
                    domain_insert_count += insert_count
                    domain_update_count += update_count
                    for a in answers:
                        _, insert_count = db_manager.insert_or_update_ip(a.address, domain_id)
                        ip_insert_count += insert_count

                        if port:
                            if mask is None:
                                hosts_grouped_by_port[port].add(a.address)
                            else:
                                hosts_grouped_by_port[port].add('%s/%s' % (a.address, mask))
                        if mask is None:
                            hosts.add(a.address)    # add domain ip for port scan
                        else:
                            hosts.add('%s/%s' % (a.address, mask))
                except Exception as e:
                    pass     # resolve failed
        db_manager.close_db()
        show_update_log(domain_insert_count=domain_insert_count, domain_update_count=domain_update_count,
                        ip_insert_count=ip_insert_count, refresh=self.db_choice.GetValue())

        """
        Some hosts were grouped by port, let's scan all groups one by one
        """
        for port in hosts_grouped_by_port:
            if self.scan_aborted:
                return
            if not hosts_grouped_by_port[port]:    # could be empty
                continue
            ip_set = IPSetStore(hosts_grouped_by_port[port])
            while True:
                ips = ip_set.get_ips(1000)
                if not ips:
                    break
                if self.scan_aborted:    # before long time running tasks, do abort check
                    return
                while self.port_scan_queue.qsize() > 1000:
                    time.sleep(0.1)
                self.port_scan_queue.put((ips, port))

        """
        Continue to process targets without port specified
        """
        ip_set = IPSetStore(hosts)
        scan_ports = conf.ports_dict[self.cbo_port_list.GetValue().replace(' ', '_')]
        while True:
            ips = ip_set.get_ips(2048)
            if not ips or self.scan_aborted:
                break

            while self.port_scan_queue.qsize() > 1000:
                time.sleep(0.1)

            if not self.chk_port_scan.GetValue():   # PING Only
                self.port_scan_queue.put(ips)
            else:
                self.port_scan_queue.put((ips, scan_ports))

    def port_scan_finished(self):
        return self.port_scan_tasks_all_entered_queue and \
               not any(self.port_scan_thread_status) and \
               self.port_scan_result_queue.qsize() == 0 and \
               self.port_scan_queue.qsize() == 0

    def port_scan_thread(self, index):
        while not self.port_scan_finished() and not self.scan_aborted and not conf.end_me:
            try:
                task = self.port_scan_queue.get(timeout=1.0)
                self.port_scan_thread_status[index] = 1   # thread busy, write db thread should wait
            except queue.Empty as e:
                self.port_scan_thread_status[index] = 0   # this thread is free now
                continue
            if type(task) is tuple:
                wx.PostEvent(conf.main_frame.target_tree,
                             LogEvent(msg='Init port scan for %s IP' % count_num_of_ips(task[0])))
                self.do_port_scan(task[0], task[1])
            else:
                wx.PostEvent(conf.main_frame.target_tree,
                             LogEvent(msg='Init port scan for %s IP' % count_num_of_ips(task)))
                self.do_ping_scan(task)

    def do_port_scan(self, ips, scan_ports):
        masscan_result = do_masscan(ips, scan_ports)
        for port in masscan_result:
            if self.scan_aborted:
                return
            ips = [ip for ip in masscan_result[port]]
            hosts = do_nmap_scan(port, ips)
            if hosts:
                self.port_scan_result_queue.put(('port_scan', hosts))

    def do_ping_scan(self, ips):
        masscan_result = do_masscan(ips, 0, ping_only=True)
        if masscan_result:
            self.port_scan_result_queue.put(('ping_scan', masscan_result))

    def refresh_cbo_databases(self):
        old_value = self.db_choice.GetValue()
        self.db_choice.Clear()
        databases = [x[0] for x in conf.target_tree_list]
        for db in databases:
            self.db_choice.Append(db)
        if old_value in databases:
            self.db_choice.SetValue(old_value)
        else:
            if conf.target_tree_list:
                self.db_choice.SetValue(conf.target_tree_list[0][0])
