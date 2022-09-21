import asyncio
import time
import wx
import os
import threading
import copy
import dns.resolver
import dns.asyncresolver
import queue
from lib.config import target_tree_list
from lib.database import DBManager
from lib.common import is_ip_addr, get_hostname_port_mask, get_abs_path, edit_ports
from lib.ip_set_store import IPSetStore
import lib.config as conf
from lib.common import set_button_img, count_num_of_ips, log_output
from ui.log import show_update_log
from lib.event import LogEvent, StatusEvent
from lib.process import do_masscan, do_nmap_scan


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


class HostDiscoverPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        lbl_enter_targets = wx.StaticText(self, -1, "Enter Targets or Drag Files")
        font = lbl_enter_targets.GetFont()
        font.MakeBold()
        lbl_enter_targets.SetFont(font)
        btn_help = wx.Button(self, -1, "", size=(30, 30), style=wx.NO_BORDER)
        btn_help.SetBitmap(wx.Image(get_abs_path('ui/resource/btn_help.png')).ConvertToBitmap(), wx.TOP)
        btn_help.SetBitmapMargins((2, 2))
        btn_help.SetBackgroundColour(wx.WHITE)
        btn_help.Bind(wx.EVT_BUTTON, self.show_targets_help)
        label_sizer = wx.BoxSizer(wx.HORIZONTAL)
        label_sizer.Add(lbl_enter_targets, 0, wx.ALIGN_CENTER_VERTICAL)
        label_sizer.Add(btn_help, 0, wx.LEFT, 10)

        self.txt_targets = wx.TextCtrl(self, -1, "", style=wx.TE_MULTILINE, size=(500, -1))
        file_drop_targets = HostsFileDropTarget(self)
        self.files_to_import = None
        self.txt_targets.SetDropTarget(file_drop_targets)
        self.txt_targets.Bind(wx.EVT_LEFT_DCLICK, self.clear_imported_file)

        self.btn_open_file = wx.Button(self, -1, "Import")
        self.btn_open_file.SetBitmap(
            wx.Image(get_abs_path('ui/resource/import_targets_16.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_open_file.SetBitmapMargins((2, 2))
        self.btn_open_file.SetInitialSize()
        self.btn_open_file.Bind(wx.EVT_BUTTON, self.import_targets)

        self.chk_port_scan = wx.CheckBox(self, -1, "PortScan")
        self.chk_port_scan.Bind(wx.EVT_CHECKBOX, self.on_port_scan_check)
        self.cbo_port_list = wx.ComboBox(self, -1, conf.port_choices[0], choices=conf.port_choices,
                                         style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.cbo_port_list.Enable(False)

        lbl_save_db = wx.StaticText(self, -1, "Save to DB")
        val = target_tree_list[0][0] if target_tree_list else ''
        self.db_choice = wx.ComboBox(self, -1, value=val, choices=[x[0] for x in target_tree_list],
                                     style=wx.CB_DROPDOWN | wx.CB_READONLY)

        left_sizer = wx.BoxSizer(wx.VERTICAL)
        left_sizer.Add(self.chk_port_scan, 0, wx.ALL, 2)
        left_sizer.Add((20, 20), 0, wx.ALL, 2)
        left_sizer.Add(lbl_save_db, 0, wx.ALL, 2)

        right_sizer = wx.BoxSizer(wx.VERTICAL)
        right_sizer.Add(self.cbo_port_list, 0, wx.ALL | wx.EXPAND, 2)
        right_sizer.Add((10, 10), 0, wx.ALL, 2)
        right_sizer.Add(self.db_choice, 0, wx.ALL | wx.EXPAND, 2)

        btn_edit_port = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        btn_edit_port.SetToolTip("Edit ports profile")
        btn_edit_port.SetBackgroundColour(wx.WHITE)
        btn_edit_port.SetBitmap(wx.Image(get_abs_path('ui/resource/edit_ports.png')).ConvertToBitmap())
        btn_edit_port.Bind(wx.EVT_BUTTON, self.edit_port_profile)

        config_sizer = wx.BoxSizer(wx.HORIZONTAL)
        config_sizer.Add(left_sizer, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 2)
        config_sizer.Add(right_sizer, 0, wx.ALL, 2)
        config_sizer.Add((5, -1))
        config_sizer.Add(btn_edit_port, 0, wx.ALL, 2)
        config_sizer.Add((-1, -1), 1, wx.EXPAND)
        config_sizer.Add(self.btn_open_file, 0, wx.ALIGN_TOP, 15)

        self.btn_scan = wx.Button(self, -1, "Scan")
        self.btn_scan.SetBitmap(wx.Image(get_abs_path('ui/resource/start_btn.png')).ConvertToBitmap(), wx.LEFT)
        self.btn_scan.SetBitmapMargins((2, 2))
        self.btn_scan.SetInitialSize()
        self.btn_scan.Bind(wx.EVT_BUTTON, self.host_discover_start)
        self.indicator = wx.ActivityIndicator(self)
        self.indicator.Hide()
        button_sizer = wx.BoxSizer(wx.HORIZONTAL)
        button_sizer.Add(self.btn_scan, 0, wx.ALL, 2)
        button_sizer.Add((20, 20), 0, wx.ALL, 2)
        button_sizer.Add(self.indicator, 0, wx.LEFT | wx.TOP, 10)

        content_sizer = wx.BoxSizer(wx.VERTICAL)
        content_sizer.Add((10, 10))
        content_sizer.Add(label_sizer, 0, wx.LEFT | wx.RIGHT, 15)
        content_sizer.Add(self.txt_targets, 1, wx.LEFT | wx.RIGHT, 15)
        content_sizer.Add((0, 2))
        content_sizer.Add((10, 10), 0, wx.ALL, 2)
        content_sizer.Add(config_sizer, 0, wx.LEFT | wx.RIGHT | wx.EXPAND, 15)
        content_sizer.Add(button_sizer, 0, wx.ALL, 15)
        self.sizer = sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add((25, -1))
        sizer.Add(content_sizer, 0, wx.EXPAND)
        sizer.AddStretchSpacer(1)
        self.SetSizer(sizer)
        self.scan_aborted = None
        self.sync_db_thread_exit = False
        self.scan_queue = queue.Queue()
        self.scan_result_queue = queue.Queue()
        self.scan_threads = []
        self.scan_thread_status = None
        self.scan_tasks_all_entered_queue = None
        self.loop = None
        self.domain_queue = None
        self.domain_result_queue = None

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

    def host_discover_start(self, event):
        if self.btn_scan.GetLabel() == 'Stop':
            self.scan_aborted = True
            conf.host_discover_aborted = True
            self.btn_scan.Enable(False)
            log_output('Host discover aborted, wait a few seconds...')
            conf.main_frame.statusBar.SetStatusText('Host discover was aborted')
            while self.scan_queue.qsize() > 0:    # empty the scan queue for later reuse
                try:
                    self.scan_queue.get_nowait()
                except Exception as e:
                    pass
            return

        if not self.files_to_import and len(self.txt_targets.GetValue()) < 4:
            wx.MessageDialog(self, 'No targets input', 'Invalid Input', wx.ICON_WARNING).ShowModal()
            return

        selected_db = self.db_choice.GetValue()
        if not selected_db or not os.path.exists(os.path.join(conf.root_path, 'database/' + selected_db)):
            wx.MessageDialog(self, 'Target database not found', 'Host Discover', wx.ICON_WARNING).ShowModal()
            return
        self.scan_aborted = False
        conf.host_discover_aborted = False
        self.enable_input(False)
        self.btn_scan.SetLabel('Stop')
        set_button_img(self.btn_scan, get_abs_path('ui/resource/brute_stop.png'))
        self.indicator.Show()
        self.sizer.Layout()
        self.indicator.Start()
        msg = 'Host discover start'
        log_output(msg)
        conf.main_frame.statusBar.SetStatusText(msg)
        threading.Thread(target=self.do_host_discovery).start()

    def enable_input(self, status):
        self.txt_targets.Enable(status)
        self.btn_open_file.Enable(status)
        self.chk_port_scan.Enable(status)
        self.cbo_port_list.Enable(status)
        self.db_choice.Enable(status)

    def ensure_queue_cleared(self):
        # aborted task may cause scan queue still remain tasks
        while self.scan_queue.qsize() > 0:
            try:
                self.scan_queue.get_nowait()
            except Exception as e:
                pass
        while self.scan_result_queue.qsize() > 0:
            try:
                self.scan_result_queue.get_nowait()
            except Exception as e:
                pass

    def do_host_discovery(self):
        self.scan_thread_status = [1 for _ in range(conf.max_num_of_scan_process)]
        for index in range(conf.max_num_of_scan_process):
            t = threading.Thread(target=self.scan_thread, args=(index,))
            self.scan_threads.append(t)
            t.start()
        self.sync_db_thread_exit = False
        threading.Thread(target=self.sync_db_thread).start()
        self.scan_tasks_all_entered_queue = False
        if not self.files_to_import:
            # input from textbox
            self.process_host_scan(self.txt_targets.GetValue())
        else:
            for path in self.files_to_import:
                if self.scan_aborted:    # abort scan, skip rest files
                    continue
                if os.path.getsize(path) > 10 * 1024 * 1024:    # ignore file of which size is greater than 10MB
                    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg="File too large, ignored: %s" % path))
                    continue
                wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='Import targets from: %s' % path))
                with open(path) as f:
                    self.process_host_scan(f.read())
        self.scan_tasks_all_entered_queue = True
        while not self.scan_finished() and not self.scan_aborted and not conf.end_me:
            time.sleep(0.1)
        while not self.sync_db_thread_exit:
            time.sleep(0.1)
        msg = 'Host discover finished.'
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg))
        wx.PostEvent(conf.main_frame, StatusEvent(text=msg))
        self.ensure_queue_cleared()
        self.enable_input(True)
        self.btn_scan.SetLabel('Scan')
        self.btn_scan.Enable(True)
        set_button_img(self.btn_scan, get_abs_path('ui/resource/portscan_start.png'))
        self.indicator.Hide()
        self.sizer.Layout()
        self.indicator.Stop()

    def sync_db_thread(self):
        db_manager = DBManager(self.db_choice.GetValue())
        while not self.scan_finished() and not self.scan_aborted and not conf.end_me:
            try:
                r_type, result = self.scan_result_queue.get(timeout=0.5)
            except Exception as e:
                continue
            if r_type == 'ping_scan':
                try:
                    for alive_ip in result[0]:
                        db_manager.insert_or_update_ip(alive_ip)
                    msg = 'Active hosts found: %s' % len(result[0])
                    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg, refresh=self.db_choice.GetValue()))
                    wx.PostEvent(conf.main_frame, StatusEvent(text=msg))
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
                except Exception as e:
                    wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg='do_port_scan.exception: %s' % str(e)))

                show_update_log(port_insert_count=port_insert_count, port_update_count=port_update_count,
                                refresh=self.db_choice.GetValue())
        db_manager.close_db()
        self.sync_db_thread_exit = True

    async def resolve_domain(self):
        resolver = dns.asyncresolver.Resolver()
        while not self.scan_aborted and not conf.end_me:
            try:
                domain, port, mask = self.domain_queue.get_nowait()
            except Exception as e:
                break
            try:
                answers = await resolver.resolve(domain, 'A', lifetime=10)  # an existed domain
                ips = [answer.address for answer in answers]
                if ips:
                    self.domain_result_queue.put_nowait((domain, port, mask, ips))
            except Exception as e:
                pass

    async def async_run(self):
        tasks = [self.resolve_domain() for i in range(50)]
        await asyncio.gather(*tasks)

    def process_host_scan(self, text):
        """
        this function is a bit complex,
        because we have to process different kinds of user input
        domain / ip / url, with or without ports
        """
        hosts = set([])
        for line in text.strip().split('\n'):
            item = line.strip().split()[0]
            if item:
                hosts.add(item)

        # resolve domain
        domain_insert_count = domain_update_count = ip_insert_count = 0
        hosts_grouped_by_port = {}    # grouped by a single port, user specified port must be scanned first

        wx.PostEvent(conf.main_frame.target_tree, LogEvent(start_timer=True, interval=300))
        self.loop = asyncio.new_event_loop()
        self.domain_queue = asyncio.Queue(loop=self.loop)
        self.domain_result_queue = asyncio.Queue(loop=self.loop)
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
                # domain input
                hosts.remove(item)
                self.domain_queue.put_nowait((hostname, port, mask))

        self.loop.run_until_complete(self.async_run())
        db_manager = DBManager(self.db_choice.GetValue())
        while self.domain_result_queue.qsize() > 0:
            domain, port, mask, ips = self.domain_result_queue.get_nowait()
            domain_id, insert_count, update_count = db_manager.insert_or_update_domain(domain)
            domain_insert_count += insert_count
            domain_update_count += update_count
            for ip in ips:
                _, insert_count = db_manager.insert_or_update_ip(ip, domain_id)
                ip_insert_count += insert_count

                if port:
                    if mask is None:
                        hosts_grouped_by_port[port].add(ip)
                    else:
                        hosts_grouped_by_port[port].add('%s/%s' % (ip, mask))
                if mask is None:
                    hosts.add(ip)    # add domain ip for port scan
                else:
                    hosts.add('%s/%s' % (ip, mask))

        db_manager.close_db()
        show_update_log(domain_insert_count=domain_insert_count, domain_update_count=domain_update_count,
                        ip_insert_count=ip_insert_count, refresh=self.db_choice.GetValue())

        self.loop = None
        self.domain_queue = None
        self.domain_result_queue = None
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(stop_timeer=True))

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
                while self.scan_queue.qsize() > 1000:
                    time.sleep(0.1)
                self.scan_queue.put((ips, port))

        """
        Continue to process targets without port specified
        """
        ip_set = IPSetStore(hosts)
        scan_ports = conf.ports_dict[self.cbo_port_list.GetValue().replace(' ', '_')]
        while True:
            ips = ip_set.get_ips(2048)
            if not ips or self.scan_aborted:
                break
            while self.scan_queue.qsize() > 1000:
                time.sleep(0.1)

            if not self.chk_port_scan.GetValue():   # PING Only
                self.scan_queue.put(ips)
            else:
                self.scan_queue.put((ips, scan_ports))

    def scan_finished(self):
        return self.scan_tasks_all_entered_queue and \
               not any(self.scan_thread_status) and \
               self.scan_result_queue.qsize() == 0 and \
               self.scan_queue.qsize() == 0

    def scan_thread(self, index):
        while not self.scan_finished() and not self.scan_aborted and not conf.end_me:
            try:
                task = self.scan_queue.get(timeout=1.0)
                self.scan_thread_status[index] = 1   # thread busy
            except queue.Empty as e:
                self.scan_thread_status[index] = 0   # thread is free now
                continue
            # to ensure thread safe
            # use PostEvent instead of directly use wx.LogMessage in a separate thread
            if type(task) is tuple:
                msg = 'Init port scan for %s IP' % count_num_of_ips(task[0])
                wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg))
                wx.PostEvent(conf.main_frame, StatusEvent(text=msg))
                self.do_port_scan(task[0], task[1])
            else:
                msg = 'Init ping scan for %s IP' % count_num_of_ips(task)
                wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg))
                wx.PostEvent(conf.main_frame, StatusEvent(text=msg))
                self.do_ping_scan(task)

    def do_port_scan(self, ips, scan_ports):
        masscan_result = do_masscan(ips, scan_ports, source='host_discover')
        for port in masscan_result:
            if self.scan_aborted:
                return
            ips = [ip for ip in masscan_result[port]]
            hosts = do_nmap_scan(port, ips, source='host_discover')
            if hosts:
                self.scan_result_queue.put(('port_scan', hosts))

    def do_ping_scan(self, ips):
        masscan_result = do_masscan(ips, 0, ping_only=True, source='host_discover')
        if masscan_result:
            self.scan_result_queue.put(('ping_scan', masscan_result))


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    win = HostDiscoverPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
