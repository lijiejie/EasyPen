#!/usr/bin/env python

import wx
import lib.config as conf
from wx.lib.agw.thumbnailctrl import ThumbnailCtrl, NativeImageHandler
from wx.lib.agw.scrolledthumbnail import EVT_THUMBNAILS_SEL_CHANGED, EVT_THUMBNAILS_DCLICK
import wx.lib.agw.scrolledthumbnail
from ui.tools.thumb import *
from ui.tools.panel_tools_index import ToolIndex
from ui.tools.tools_ui.git_hack import GitHackPanel
from ui.tools.tools_ui.ds_store_exp import DsStoreExpPanel
from ui.tools.tools_ui.idea_exploit import IdeaExploitPanel
from ui.tools.tools_ui.iis_shortname_scanner import IISShortNameScannerPanel
from ui.tools.tools_ui.sub_domains_brute import SubDomainsBrutePanel
from ui.tools.tools_ui.swagger_exp import SwaggerExpPanel


class ToolsPanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1)
        self.tool_list = {}
        self.init_left_panel()
        self.right_panel = ToolIndex(self)
        self.current_right_panel = 'index'
        self.tool_list['index'] = self.right_panel
        self.sizer = sizer = wx.BoxSizer(wx.HORIZONTAL)
        sizer.Add(self.left_panel, 0, wx.EXPAND)
        sizer.Add((10, 10))
        sizer.Add(self.right_panel, 1, wx.EXPAND)
        self.SetSizer(sizer)
        self.Fit()

    def init_left_panel(self):
        self.left_panel = left_panel = wx.Panel(self, size=(-1, -1))
        self.keyword = wx.SearchCtrl(left_panel, style=wx.TE_PROCESS_ENTER, size=(150, -1))
        self.keyword.Bind(wx.EVT_CHAR_HOOK, self.do_search)
        self.scroll = scroll = ThumbnailCtrl(left_panel, -1, size=(150, -1), imagehandler=NativeImageHandler)
        scroll.SetCaptionFont(wx.Font(9, wx.FONTFAMILY_SWISS, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD, False))
        scroll.ShowFileNames(True)
        self.do_search(None)

        for tool in self.scroll.ListDirectory(os.path.join(conf.root_path, 'ui/resource/tools'), ['.png', '.jpg']):
            self.tool_list[tool.lower()[:-4]] = None
        scroll.SetThumbOutline(wx.lib.agw.scrolledthumbnail.THUMB_OUTLINE_FULL)
        scroll.SetHighlightPointed(True)
        scroll.SetSelectionColour(wx.Colour(128, 128, 128))
        scroll.SetThumbSize(128, 64)
        self.scroll.Bind(EVT_THUMBNAILS_DCLICK, self.open_tool)
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add((-1, 10))
        sizer.Add(self.keyword, 0, wx.EXPAND)
        sizer.Add(scroll, 1)
        left_panel.SetSizer(sizer)
        scroll._scrolled.ShowScrollbars(wx.SHOW_SB_NEVER, wx.SHOW_SB_DEFAULT)

    def do_search(self, event):
        self.scroll.keyword = self.keyword.GetValue().strip()
        self.scroll.ShowDir(os.path.join(conf.root_path, 'ui/resource/tools'))
        if event:
            event.Skip()

    def open_tool(self, event):
        item = self.scroll.GetItem(self.scroll.GetSelection())
        caption = item._caption.lower()[:-4]
        self.Freeze()
        if not self.tool_list[caption]:
            self.tool_list[caption] = self.create_tool(caption)

        self.right_panel.Hide()
        self.sizer.Detach(self.right_panel)
        self.right_panel = self.tool_list[caption]
        self.right_panel.Show()
        self.sizer.Add(self.right_panel, 1, wx.EXPAND)
        self.Layout()
        self.Thaw()

        event.Skip()

    def create_tool(self, caption):
        if caption == 'githack':
            return GitHackPanel(self)
        elif caption == 'ds_store_exp':
            return DsStoreExpPanel(self)
        elif caption == 'idea_exploit':
            return IdeaExploitPanel(self)
        elif caption == 'iis_shortname_scanner':
            return IISShortNameScannerPanel(self)
        elif caption == 'subdomainsbrute':
            return SubDomainsBrutePanel(self)
        elif caption == 'swagger-exp':
            return SwaggerExpPanel(self)
        else:
            return GitHackPanel(self)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = wx.Frame(None, -1, "Test", size=(850, 500))
    win = ToolsPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
