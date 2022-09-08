import wx
from ui.dicover.panel_name_brute import NameBrutePanel
from ui.dicover.panel_host_discover import HostDiscoverPanel
import lib.config as conf


class DiscoverPanel(wx.Panel):
    def __init__(self, frame):
        wx.Panel.__init__(self, frame.notebook, -1, style=wx.CLIP_CHILDREN)
        self.notebook = wx.Notebook(self, -1, style=wx.CLIP_CHILDREN)
        self.brute_panel = brute_panel = NameBrutePanel(self.notebook)
        self.host_discover_panel = HostDiscoverPanel(self.notebook)
        self.notebook.AddPage(brute_panel, " Domain Brute ")
        self.notebook.AddPage(self.host_discover_panel, " Host Discover ")
        self.sizer = sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.notebook, 1, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(sizer)

    # called by panel_left.add_target
    def add_target(self, target):
        self.brute_panel.db_choice.Append(target)
        if self.brute_panel.btn_brute.GetLabelText() != 'Stop':   # no running jobs
            self.brute_panel.db_choice.SetValue(conf.target_tree_list[0][0])

        self.host_discover_panel.db_choice.Append(target)
        if self.host_discover_panel.btn_scan.GetLabelText() != 'Stop':    # no running jobs
            self.host_discover_panel.db_choice.SetValue(conf.target_tree_list[0][0])

    def refresh_cbo_databases(self):
        brute_panel = self.brute_panel
        old_value = brute_panel.db_choice.GetValue()
        brute_panel.db_choice.Clear()
        for x in conf.target_tree_list:
            brute_panel.db_choice.Append(x[0])
        if old_value in [t[0] for t in conf.target_tree_list]:
            brute_panel.db_choice.SetValue(old_value)
        else:
            if conf.target_tree_list:
                brute_panel.db_choice.SetValue(conf.target_tree_list[0][0])

        host_discover_panel = self.host_discover_panel
        old_value = host_discover_panel.db_choice.GetValue()
        host_discover_panel.db_choice.Clear()
        for x in conf.target_tree_list:
            host_discover_panel.db_choice.Append(x[0])
        if conf.target_tree_list:
            host_discover_panel.db_choice.SetValue(conf.target_tree_list[0][0])
        if old_value in [t[0] for t in conf.target_tree_list]:
            host_discover_panel.db_choice.SetValue(old_value)
        else:
            if conf.target_tree_list:
                host_discover_panel.db_choice.SetValue(conf.target_tree_list[0][0])


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(950, 600))
    main_panel = wx.Panel(frame, -1, size=(850, 500))
    frame.notebook = wx.Notebook(main_panel, -1, style=wx.CLIP_CHILDREN, size=(850, 500))
    discover_panel = DiscoverPanel(frame)
    frame.notebook.AddPage(discover_panel, "Discover")
    frame.notebook.Layout()
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
