import wx
from lib.common import get_abs_path
import lib.config as conf


class GeneralSettingsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        label_title = wx.StaticText(self, -1, 'General Settings')
        font = label_title.GetFont()
        font.MakeBold()
        label_title.SetFont(font)
        label_title.SetBackgroundColour((230, 230, 250))
        label_user_agent = wx.StaticText(self, -1, 'User Agent (used by nmap and all scan scripts)')
        self.txt_user_agent = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE, size=(400, 60))
        self.txt_user_agent.SetValue(conf.global_user_agent)

        self.chk_enable_proxy = wx.CheckBox(self, -1, 'Enable HTTP Proxy')
        label_http_proxy = wx.StaticText(self, -1, 'http proxy ->  http://username:password@localhost:8000 ')
        label_socks_proxy = wx.StaticText(self, -1, 'socks proxy ->  socks5://user:pass@host:port ')
        label_http_proxy.SetForegroundColour((72, 118, 255))
        label_socks_proxy.SetForegroundColour((72, 118, 255))
        self.chk_enable_proxy.SetValue(conf.global_proxy_server_enabled)
        self.txt_http_proxy = wx.TextCtrl(self, -1, size=(354, -1))
        self.txt_http_proxy.SetValue(conf.global_proxy_server)

        label_log_file_size = wx.StaticText(self, -1, 'Max size for single log file (MB)',
                                            size=(200, -1))
        self.txt_log_file_size = wx.TextCtrl(self, -1, size=(150, -1))
        self.txt_log_file_size.SetValue(str(conf.log_file_max_size))
        sizer_log_file_size = wx.BoxSizer(wx.HORIZONTAL)
        sizer_log_file_size.Add(label_log_file_size, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_log_file_size.Add(self.txt_log_file_size, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_num_of_log_files = wx.StaticText(self, -1, 'How many backup log files can be kept',
                                               size=(250, -1))
        self.cbo_num_of_log_files = wx.ComboBox(self, -1, str(conf.log_file_backup_count),
                                                choices=[str(x) for x in range(1, 16)],
                                                style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_num_of_log_files = wx.BoxSizer(wx.HORIZONTAL)
        sizer_num_of_log_files.Add(label_num_of_log_files, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_num_of_log_files.Add(self.cbo_num_of_log_files, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_ui_font_size = wx.StaticText(self, -1, 'Application UI default font size',
                                           size=(250, -1))
        self.cbo_ui_font_size = wx.ComboBox(self, -1, str(conf.global_font_size),
                                            choices=[str(x) for x in range(6, 17)],
                                            style=wx.CB_DROPDOWN | wx.CB_READONLY, size=(100, -1))
        sizer_ui_font_size = wx.BoxSizer(wx.HORIZONTAL)
        sizer_ui_font_size.Add(label_ui_font_size, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_ui_font_size.Add(self.cbo_ui_font_size, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        label_page_size = wx.StaticText(self, -1, 'Targets display page size', size=(200, -1))
        self.txt_targets_page_size = wx.TextCtrl(self, -1, size=(150, -1))
        self.txt_targets_page_size.SetValue(str(conf.targets_display_pagesize))
        sizer_targets_page_size = wx.BoxSizer(wx.HORIZONTAL)
        sizer_targets_page_size.Add(label_page_size, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)
        sizer_targets_page_size.Add(self.txt_targets_page_size, 1, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 10)

        sizer_main = wx.BoxSizer(wx.VERTICAL)
        sizer_main.Add(label_title, 0, wx.LEFT | wx.TOP | wx.EXPAND, 10)
        sizer_main.Add(label_user_agent, 0, wx.LEFT | wx.TOP, 10)
        sizer_main.Add((-1, 10))
        sizer_main.Add(self.txt_user_agent, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 20))
        sizer_main.Add(self.chk_enable_proxy, 0, wx.LEFT, 10)
        sizer_main.Add((-1, 5))
        sizer_main.Add(label_http_proxy, 0, wx.LEFT, 26)
        sizer_main.Add(label_socks_proxy, 0, wx.LEFT, 26)
        sizer_main.Add((-1, 10))

        sizer_main.Add(self.txt_http_proxy, 0, wx.LEFT, 26)
        sizer_main.Add((-1, 10))
        sizer_main.Add(sizer_log_file_size, 0)
        sizer_main.Add(sizer_num_of_log_files, 0)
        sizer_main.Add(sizer_ui_font_size, 0)
        sizer_main.Add(sizer_targets_page_size, 0)

        sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add((-1, 30))
        sizer.Add(sizer_main, 1, wx.EXPAND)
        sizer.Add((-1, 30))
        self.SetSizer(sizer)
        self.Fit()


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(850, 800))
    panel = wx.Panel(frame, -1)
    panel_git_hack = GeneralSettingsPanel(panel)
    sizer = wx.BoxSizer(wx.HORIZONTAL)
    sizer.Add(panel_git_hack, 1, wx.EXPAND)
    panel.SetSizer(sizer)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
