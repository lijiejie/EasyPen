#!/usr/bin/env python3

import wx
import os
import codecs
import lib.config as conf


class SourceCodeViewFrame(wx.Frame):
    def __init__(self, parent):
        wx.Frame.__init__(self, None, -1, "View Source Code", size=(800, 600),
                          style=wx.DEFAULT_FRAME_STYLE & ~wx.RESIZE_BORDER & ~wx.MAXIMIZE_BOX | wx.STAY_ON_TOP)
        self.parent = parent
        icon = wx.Icon()
        icon.CopyFromBitmap(wx.Image(os.path.join(conf.root_path, 'ui/resource/EasyPen.png')).ConvertToBitmap())
        self.SetIcon(icon)
        self.SetBackgroundColour('white')
        self.text = wx.TextCtrl(self, -1, style=wx.TE_MULTILINE | wx.HSCROLL | wx.TE_RICH2 | wx.TE_NOHIDESEL)

    def show_source_code(self, script_name):
        self.SetTitle("Source Code of %s" % script_name)
        path = os.path.join(conf.root_path, 'scripts/%s.py' % script_name)
        with codecs.open(path, encoding='utf-8') as f:
            self.text.WriteText(f.read())
        self.text.SetInsertionPoint(0)
        self.text.SetEditable(False)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    frame = SourceCodeViewFrame(None)
    frame.Show()
    app.MainLoop()
