import wx
import wx.lib.agw.aui as aui
import wx.lib.newevent
import webbrowser
import lib.config as conf
from ui.dicover.panel_discover import DiscoverPanel
from ui.panel_left import TargetDatabasePanel
from ui.targets.panel_target_viewer import DBViewPanel
from ui.scan.panel_scan import VulScanPanel
from ui.tools.panel_tools import ToolsPanel
from ui.settings.panel_settings import SettingsPanel
from lib.common import check_environment
from lib.event import Status_EVT_BINDER


class MainPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        font = self.GetFont()
        font.SetPointSize(conf.global_font_size)
        self.SetFont(font)

    def Freeze(self):
        if 'wxMSW' in wx.PlatformInfo:
            return super(MainPanel, self).Freeze()

    def Thaw(self):
        if 'wxMSW' in wx.PlatformInfo:
            return super(MainPanel, self).Thaw()


class ScanLog(wx.Log):
    def __init__(self, text_ctrl):
        wx.Log.__init__(self)
        self.text_ctrl = text_ctrl

    def DoLogText(self, message):
        if self.text_ctrl:
            self.text_ctrl.AppendText(message + '\n')


class MainFrame(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, -1, title, size=(970, 720),
                          style=wx.DEFAULT_FRAME_STYLE | wx.NO_FULL_REPAINT_ON_RESIZE)
        conf.main_frame = self
        self.Freeze()
        if 'wxMSW' not in wx.PlatformInfo:
            font = self.GetFont()
            font.SetPointSize(10)
            self.SetFont(font)
        self.task_list = []    # running tasks
        self.Bind(wx.EVT_IDLE, self.on_idle)
        self.menu_bar = None
        self.SetMinSize((970, 720))
        self.main_panel = main_panel = MainPanel(self)
        self.aui_mgr = aui.AuiManager()
        self.aui_mgr.SetManagedWindow(main_panel)

        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image('ui/resource/EasyPen.png').ConvertToBitmap())
        self.SetIcon(icon)

        self.Bind(wx.EVT_CLOSE, self.on_close_window)
        self.Centre(wx.BOTH)

        self.statusBar = self.CreateStatusBar(2)
        self.statusBar.SetStatusWidths([-2, -1])
        self.statusBar.SetStatusText("Welcome to EasyPen", 0)
        self.progress_bar = wx.Gauge(self.statusBar, wx.ID_ANY, 50)
        self.progress_bar.SetToolTip("Scanning...")
        self.progress_bar.Hide()
        self.progress_bar_timer = wx.Timer(self, -1)
        self.Bind(wx.EVT_TIMER, self.update_progress_bar, self.progress_bar_timer)
        self.statusbar_size_changed = False
        self.resize_progressbar()

        self.statusBar.Bind(wx.EVT_SIZE, self.on_statusbar_size)
        self.statusBar.Bind(wx.EVT_IDLE, self.on_statusbar_idle)

        conf.load_config()

        self.notebook = wx.Notebook(main_panel, -1, style=wx.CLIP_CHILDREN)
        img_list = wx.ImageList(16, 16)
        for img_name in ['targets_icon.png', 'db_view_icon.png', 'vul_scan.png',
                         'exp_icon.png', 'settings_icon.png']:
            img_list.Add(wx.Image('ui/resource/%s' % img_name).ConvertToBitmap())
        self.notebook.AssignImageList(img_list)

        self.python_shell = None
        self.build_menu_bar()

        self.discover_panel = discover_panel = DiscoverPanel(self)
        self.db_panel = db_panel = DBViewPanel(self)

        self.left_panel = left_panel = TargetDatabasePanel(main_panel, self)
        self.target_tree = left_panel.target_tree
        self.target_filter = left_panel.target_filter

        self.scan_panel = scan_panel = VulScanPanel(self)
        self.tools_panel = tools_panel = ToolsPanel(self.notebook)
        self.settings_panel = settings_panel = SettingsPanel(self)

        self.notebook.AddPage(discover_panel, "Discover", imageId=0)
        self.notebook.AddPage(db_panel, "Targets", imageId=1)
        self.notebook.AddPage(scan_panel, "Scanner", imageId=2)
        self.notebook.AddPage(tools_panel, "Tools", imageId=3)
        self.notebook.AddPage(settings_panel, "Settings", imageId=4)
        self.notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.on_page_changed)
        self.notebook.SetSelection(2)    # default tab set to scanner

        self.log = wx.TextCtrl(main_panel, -1, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL)
        self.log.Bind(wx.EVT_RIGHT_DOWN, self.on_mouse_right_down)
        if wx.Platform == "__WXMAC__":
            self.log.MacCheckSpelling(False)
        wx.Log.SetActiveTarget(ScanLog(self.log))

        self.aui_mgr.AddPane(self.notebook, aui.AuiPaneInfo().CenterPane().Name("Notebook").MinSize(-1, 420))
        self.aui_mgr.AddPane(left_panel,
                             aui.AuiPaneInfo().Left().Layer(2).BestSize((200, -1)).
                             MinSize((200, -1)).MaxSize((210, -1)).
                             Floatable(False).CloseButton(False).Name("TargetsTree"))
        self.aui_mgr.AddPane(self.log,
                             aui.AuiPaneInfo().Bottom().BestSize((-1, 150)).MinSize((-1, 140)).
                             Floatable(False).Caption("Log Messages").CloseButton(False).Name("LogWindow"))
        self.aui_mgr.Update()
        self.aui_mgr.SetAGWFlags(self.aui_mgr.GetAGWFlags() ^ aui.AUI_MGR_TRANSPARENT_DRAG)
        wx.CallLater(1000, check_environment, self)
        self.Bind(Status_EVT_BINDER, self.update_status_text)
        self.Thaw()

    def update_status_text(self, event):
        if hasattr(event, 'text'):
            self.statusBar.SetStatusText(event.text)

    def update_progress_bar(self, event):
        self.progress_bar.Pulse()

    def on_mouse_right_down(self, event):
        point = event.GetPosition()
        menu = wx.Menu()
        clear_all_item = wx.MenuItem(menu, -1, 'Clear All')
        menu.Append(clear_all_item)
        clear_all_item.SetBitmap(wx.Image('ui/resource/delete-target.png').ConvertToBitmap())
        self.Bind(wx.EVT_MENU, self.clear_logs, clear_all_item)
        self.log.PopupMenu(menu, point)
        menu.Destroy()

    def clear_logs(self, event):
        self.log.Clear()
        event.Skip()

    def on_page_changed(self, event):
        if event.EventObject == self.notebook:
            if event.GetSelection() == 1 and not self.db_panel.grid.created:
                if conf.target_tree_list:
                    wx.CallLater(200, self.db_panel.do_search, (None,))

    def on_idle(self, evt):
        evt.Skip()

    def build_menu_bar(self):
        self.menu_bar = wx.MenuBar()
        menu = wx.Menu()
        item = wx.MenuItem(menu, wx.ID_EXIT, 'E&xit\tCtrl-Q', 'Exit EasyPen')
        # item.SetBitmap(wx.Image('ui/resource/exit.png').ConvertToBitmap())
        menu.Append(item)
        self.Bind(wx.EVT_MENU, self.menu_exit, item)
        self.menu_bar.Append(menu, '&File')

        # Make a Help menu
        menu = wx.Menu()
        docs_item = wx.MenuItem(menu, -1, 'Docs')
        menu.Append(docs_item)
        shell_item = wx.MenuItem(menu, -1, 'Python &Shell\tF5', 'Python interpreter')
        shell_item.SetBitmap(wx.Image('ui/resource/python_shell.png').ConvertToBitmap())
        menu.Append(shell_item)

        update_item = wx.MenuItem(menu, -1, 'Check Update')
        update_item.SetBitmap(wx.Image('ui/resource/check_update.png').ConvertToBitmap())
        menu.Append(update_item)

        if 'wxMac' not in wx.PlatformInfo:
            menu.AppendSeparator()
        help_item = menu.Append(wx.ID_ABOUT, '&About', 'About EasyPen')

        self.Bind(wx.EVT_MENU, self.view_docs, docs_item)
        self.Bind(wx.EVT_MENU, self.open_python_shell, shell_item)
        self.Bind(wx.EVT_MENU, self.help_about, help_item)
        self.Bind(wx.EVT_MENU, self.check_update, update_item)
        self.menu_bar.Append(menu, '&Help')
        self.SetMenuBar(self.menu_bar)

    def on_statusbar_size(self, evt):
        self.resize_progressbar()
        self.statusbar_size_changed = True

    def on_statusbar_idle(self, evt):
        if self.statusbar_size_changed:
            self.resize_progressbar()

    def resize_progressbar(self):
        rect = self.statusBar.GetFieldRect(1)
        self.progress_bar.SetPosition((rect.x + 2, rect.y + 2))
        self.progress_bar.SetSize((rect.width - 4, rect.height - 4))
        self.statusbar_size_changed = False

    def menu_exit(self, event):
        self.Close()

    def help_about(self, event):
        from ui.dialog_about import AboutDialog
        about = AboutDialog(self)
        about.ShowModal()
        about.Destroy()

    def check_update(self, event):
        wx.LogMessage('Update function not yet implemented, please go check https://github.com/lijiejie/EasyPen')
        wx.LogMessage('Run git pull to fetch updated source code files')
        webbrowser.open_new_tab('https://github.com/lijiejie/EasyPen')

    def view_docs(self, event):
        webbrowser.open_new_tab('https://easypen.lijiejie.com/')
        wx.LogMessage('If browser failed to open, please go check https://easypen.lijiejie.com/')

    def open_python_shell(self, event):
        if self.python_shell:
            s = self.python_shell
            if s.IsIconized():
                s.Iconize(False)
            s.Raise()
        else:
            from wx import py
            namespace = {'wx': wx, 'app': wx.GetApp(), 'frame': self}
            self.python_shell = py.shell.ShellFrame(None, locals=namespace)
            self.python_shell.SetSize((640, 480))
            self.python_shell.Center()
            self.python_shell.Show()

            def close_shell(evt):
                if self.python_shell:
                    self.python_shell.Close()
                evt.Skip()
            self.Bind(wx.EVT_CLOSE, close_shell)

    def on_close_window(self, event):
        if self.task_list:
            # Force kill running scan process
            dlg = wx.MessageDialog(self,
                                   'Running tasks will be terminated immediately.\n'
                                   'Data lose can happen. Exit anyway?', 'EasyPen',
                                   wx.YES_NO | wx.ICON_INFORMATION)
            if dlg.ShowModal() != wx.ID_YES:
                return
            wx.Kill(self.discover_panel.brute_panel.job_list[
                        self.discover_panel.brute_panel.running_index], wx.SIGKILL)

        self.aui_mgr.UnInit()
        conf.end_me = True
        self.menu_bar = None
        # conf.save_config(self)
        self.Destroy()
