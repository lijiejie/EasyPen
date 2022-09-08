import wx
import lib.config as conf
from lib.common import get_abs_path
from ui.scan.panel_scripts_list import ScriptListCtrlPanel
from ui.scan.panel_scan_results import ResultListCtrlPanel
from ui.scan.box_targets_input import VulnerabilityScanBox


class VulScanPanel(wx.Panel):
    def __init__(self, frame):
        wx.Panel.__init__(self, frame.notebook, -1, style=wx.CLIP_CHILDREN)
        self.frame = frame
        self.notebook = wx.Notebook(self, -1, style=wx.CLIP_CHILDREN)
        self.scripts_panel = ScriptListCtrlPanel(self.notebook)
        self.scan_box = VulnerabilityScanBox(self)
        self.result_panel = ResultListCtrlPanel(self.notebook, self.scan_box.db_choice)
        self.notebook.AddPage(self.scripts_panel, "  Scripts  ")
        self.notebook.AddPage(self.result_panel, "  Results  ")
        self.sizer = sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.notebook, 1, wx.LEFT | wx.RIGHT | wx.TOP | wx.EXPAND, 10)
        sizer.Add(self.scan_box.sizer, 0, wx.LEFT | wx.RIGHT | wx.EXPAND, 10)
        self.SetSizer(sizer)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(950, 550))
    main_panel = wx.Panel(frame, -1, size=(950, 550))
    frame.notebook = wx.Notebook(main_panel, -1, style=wx.CLIP_CHILDREN, size=(850, 500))
    discover_panel = VulScanPanel(frame)
    frame.notebook.AddPage(discover_panel, "Scanner")
    frame.notebook.Layout()
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
