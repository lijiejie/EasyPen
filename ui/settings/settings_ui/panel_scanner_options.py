import wx
from lib.common import get_abs_path
import lib.config as conf


class ScannerOptionsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        label_title = wx.StaticText(self, -1, 'Scanner Options')
        font = label_title.GetFont()
        font.MakeBold()
        label_title.SetFont(font)
        label_title.SetBackgroundColour((230, 230, 250))

        label_scan_threads = wx.StaticText(self, -1, 'Num of scan threads (100 ~ 2000)',
                                           size=(250, -1))
        self.txt_scan_threads = wx.TextCtrl(self, -1, size=(100, -1))
        self.txt_scan_threads.SetValue(str(conf.scan_threads_num))
        sizer_scan_threads = wx.BoxSizer(wx.HORIZONTAL)
        sizer_scan_threads.Add(label_scan_threads, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_scan_threads.Add(self.txt_scan_threads, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_timeout = wx.StaticText(self, -1, 'Timeout for non-brute task (minutes)',
                                      size=(250, -1))
        self.txt_task_timeout = wx.TextCtrl(self, -1, size=(100, -1))
        self.txt_task_timeout.SetValue(str(conf.normal_scan_task_timeout))
        sizer_task_timeout = wx.BoxSizer(wx.HORIZONTAL)
        sizer_task_timeout.Add(label_timeout, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_task_timeout.Add(self.txt_task_timeout, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        self.chk_enable_weak_pass_brute = wx.CheckBox(self, -1, 'Enable password brute with hydra / medusa')
        self.chk_enable_weak_pass_brute.SetValue(conf.brute_scan_enabled)

        label_num_of_hydra_medusa = wx.StaticText(self, -1, 'Multi-Process of medusa / hydra / ncrack',
                                                  size=(250, -1))
        self.cbo_scan_process = wx.ComboBox(self, -1, str(conf.brute_process_num),
                                            choices=[str(x) for x in range(1, 21)],
                                            style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_num_of_scan_process = wx.BoxSizer(wx.HORIZONTAL)
        sizer_num_of_scan_process.Add(label_num_of_hydra_medusa, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 20)
        sizer_num_of_scan_process.Add(self.cbo_scan_process, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_brute_timeout = wx.StaticText(self, -1, 'Timeout for brute task (minutes)', size=(250, -1))
        self.txt_brute_task_timeout = wx.TextCtrl(self, -1, size=(100, -1))
        self.txt_brute_task_timeout.SetValue(str(conf.brute_task_timeout))
        sizer_brute_task_timeout = wx.BoxSizer(wx.HORIZONTAL)
        sizer_brute_task_timeout.Add(label_brute_timeout, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 20)
        sizer_brute_task_timeout.Add(self.txt_brute_task_timeout, 1, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 10)

        label_preferred_tool = wx.StaticText(self, -1, 'Which tool do you prefer to use', size=(250, -1))
        self.cbo_preferred_tool = wx.ComboBox(self, -1, str(conf.brute_tool_preferred),
                                              choices=['hydra', 'medusa'],
                                              style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_preferred_tool = wx.BoxSizer(wx.HORIZONTAL)
        sizer_preferred_tool.Add(label_preferred_tool, 0, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 20)
        sizer_preferred_tool.Add(self.cbo_preferred_tool, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        label_medusa_warning = wx.StaticText(self, -1, 'medusa -d to check if rdp module enabled', size=(300, -1))
        label_medusa_warning.SetForegroundColour((0, 139, 139))

        self.chk_enable_dnslog = wx.CheckBox(self, -1, 'Enable DNS log to help detect vulnerabilities')
        self.chk_enable_dnslog.SetValue(conf.dnslog_enabled)
        label_dnslog_warning = wx.StaticText(self, -1, 'Register account: http://eyes.sh',
                                             size=(300, -1))
        label_dnslog_warning.SetForegroundColour((0, 139, 139))
        label_dnslog_warning2 = wx.StaticText(self, -1, 'Deploy self-hosted: https://github.com/lijiejie/eyes.sh',
                                              size=(400, -1))
        label_dnslog_warning2.SetForegroundColour((0, 139, 139))

        label_dnslog_postfix = wx.StaticText(self, -1, 'Postfix',
                                             size=(80, -1))
        self.txt_dnslog_postfix = wx.TextCtrl(self, -1, size=(200, -1))
        self.txt_dnslog_postfix.SetValue(conf.dnslog_domain_postfix)
        sizer_dnslog_postfix = wx.BoxSizer(wx.HORIZONTAL)
        sizer_dnslog_postfix.Add(label_dnslog_postfix, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 30)
        sizer_dnslog_postfix.Add(self.txt_dnslog_postfix, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        label_dnslog_user = wx.StaticText(self, -1, 'User', size=(80, -1))
        self.txt_dnslog_user = wx.TextCtrl(self, -1, size=(200, -1))
        self.txt_dnslog_user.SetValue(conf.dnslog_user)
        sizer_dnslog_user = wx.BoxSizer(wx.HORIZONTAL)
        sizer_dnslog_user.Add(label_dnslog_user, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 30)
        sizer_dnslog_user.Add(self.txt_dnslog_user, 1, wx.LEFT | wx.DOWN | wx.ALIGN_CENTER_VERTICAL, 5)

        label_dnslog_token = wx.StaticText(self, -1, 'Token', size=(80, -1))
        self.txt_dnslog_token = wx.TextCtrl(self, -1, size=(200, -1), style=wx.TE_PASSWORD)
        self.txt_dnslog_token.SetValue(conf.dnslog_token)
        sizer_dnslog_token = wx.BoxSizer(wx.HORIZONTAL)
        sizer_dnslog_token.Add(label_dnslog_token, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 30)
        sizer_dnslog_token.Add(self.txt_dnslog_token, 1, wx.LEFT | wx.DOWN | wx.ALIGN_CENTER_VERTICAL, 5)

        label_dnslog_api_server = wx.StaticText(self, -1, 'API Server', size=(80, -1))
        self.txt_dnslog_api_server = wx.TextCtrl(self, -1, size=(200, -1))
        self.txt_dnslog_api_server.SetValue(conf.dnslog_api_server)
        sizer_dnslog_api_server = wx.BoxSizer(wx.HORIZONTAL)
        sizer_dnslog_api_server.Add(label_dnslog_api_server, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 30)
        sizer_dnslog_api_server.Add(self.txt_dnslog_api_server, 1, wx.LEFT | wx.ALIGN_CENTER_VERTICAL, 5)

        label_dns_zones = wx.StaticText(self, -1, 'DNS Zone Transfer Scan (Enter new line delimited domains)')
        self.txt_dns_zones = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(400, 80))
        self.txt_dns_zones.SetValue(conf.dns_zone_transfer_domains)

        label_ldap_server = wx.StaticText(self, -1, 'Ldap Log Server to help detect log4j vulnerabilities')
        label_ldap_server2 = wx.StaticText(self, -1, 'Leave blank if you not yet get one')
        self.txt_ldap_server = wx.TextCtrl(self, -1, size=(400, -1))
        self.txt_ldap_server.SetValue(conf.ldap_log_server)

        self.chk_enable_plugin_debug = wx.CheckBox(self, -1, 'Enable plugin debug logging (poc_runner.log)')
        self.chk_enable_plugin_debug.SetValue(conf.enable_plugin_debug)

        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(label_title, 0, wx.LEFT | wx.TOP | wx.EXPAND, 10)
        sizer_main.Add(sizer_scan_threads, 0)
        sizer_main.Add(sizer_task_timeout, 0)
        sizer_main.Add((-1, 10))
        sizer_main.Add(self.chk_enable_weak_pass_brute, 0, wx.LEFT | wx.TOP, 10)
        sizer_main.Add(sizer_num_of_scan_process, 0)
        sizer_main.Add(sizer_brute_task_timeout, 0)
        sizer_main.Add(sizer_preferred_tool, 0)
        sizer_main.Add(label_medusa_warning, 0, wx.LEFT, 20)
        sizer_main.Add((-1, 10))
        sizer_main.Add(self.chk_enable_dnslog, 0, wx.LEFT | wx.TOP, 10)
        sizer_main.Add(sizer_dnslog_postfix, 0)
        sizer_main.Add(sizer_dnslog_user, 0)
        sizer_main.Add(sizer_dnslog_token, 0)
        sizer_main.Add(sizer_dnslog_api_server, 0)
        sizer_main.Add(label_dnslog_warning, 0, wx.LEFT, 30)
        sizer_main.Add(label_dnslog_warning2, 0, wx.LEFT, 30)
        sizer_main.Add((-1, 20))
        sizer_main.Add(label_dns_zones, 0, wx.LEFT, 10)
        sizer_main.Add(self.txt_dns_zones, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 20))
        sizer_main.Add(label_ldap_server, 0, wx.LEFT, 10)
        sizer_main.Add(label_ldap_server2, 0, wx.LEFT, 10)
        sizer_main.Add(self.txt_ldap_server, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 20))
        sizer_main.Add(self.chk_enable_plugin_debug, 0, wx.LEFT, 10)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add((-1, 30))
        sizer.Add(sizer_main, 1, wx.EXPAND)
        sizer.Add((-1, 30))
        self.SetSizer(sizer)
        self.Layout()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 800))
    panel = wx.Panel(frame, -1)
    panel_git_hack = ScannerOptionsPanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
