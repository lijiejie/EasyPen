#!/usr/bin/env python

import wx
import queue
import wx.lib.mixins.listctrl as list_mix
import lib.config as conf
from lib.common import get_abs_path
from lib.event import Vul_EVT_BINDER, LogEvent
from lib.database import DBManager
from ui.scan.frame_scan_result_viewer import ScanResultViewFrame


class ResultListCtrl(wx.ListCtrl, list_mix.ListCtrlAutoWidthMixin):
    def __init__(self, parent, pos=wx.DefaultPosition, size=wx.DefaultSize, style=0):
        wx.ListCtrl.__init__(self, parent, -1, pos, size, style)
        list_mix.ListCtrlAutoWidthMixin.__init__(self)


class ResultListCtrlPanel(wx.Panel, list_mix.ColumnSorterMixin):
    def __init__(self, parent, db_choice):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS)
        self.parent_note_book = parent
        self.db_choice = db_choice
        conf.result_list_ctrl_panel = self
        # image list
        self.image_list = wx.ImageList(16, 16)
        self.img_0 = self.image_list.Add(wx.Image(get_abs_path("ui/resource/bug.png")).ConvertToBitmap())
        self.sort_up = self.image_list.Add(wx.Image(get_abs_path("ui/resource/sort_up.png")).ConvertToBitmap())
        self.sort_down = self.image_list.Add(wx.Image(get_abs_path("ui/resource/sort_down.png")).ConvertToBitmap())
        self.list = ResultListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN)
        self.list.SetImageList(self.image_list, wx.IMAGE_LIST_SMALL)

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.list, 1, wx.EXPAND)
        self.list.EnableCheckBoxes(enable=False)
        self.itemDataMap = {}
        self.populate_list()
        list_mix.ColumnSorterMixin.__init__(self, 4)

        self.SetSizer(sizer)
        self.SetAutoLayout(True)

        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.update_current_item, self.list)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.update_current_item, self.list)

        self.list.Bind(wx.EVT_LEFT_DCLICK, self.view_vulnerability_details)

        self.list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.popup_menu)    # for wxMSW
        self.list.Bind(wx.EVT_RIGHT_UP, self.popup_menu)    # for wxGTK
        self.current_item = None
        self.id_popup_copy = wx.NewIdRef()
        self.id_popup_dump = wx.NewIdRef()
        self.result_queue = queue.Queue()
        self.Bind(Vul_EVT_BINDER, self.save_vulnerability)
        self.db_manager = None
        self.Bind(wx.EVT_IDLE, self.on_idle)

    def save_vulnerability(self, event):
        for vul in event.vul:
            self.result_queue.put(vul)

    def on_idle(self, event):
        if self.result_queue.qsize() == 0:
            event.Skip()
            return
        vul = self.result_queue.get()
        if not self.db_manager:
            self.db_manager = DBManager(self.db_choice.GetValue())
        vul_id, create_time, insert_count, update_count = self.db_manager.insert_or_update_vul(vul)
        if insert_count:
            msg = 'New: [%s] -> %s' % (vul['alert_group'].lower(), vul['affects'])
        else:
            msg = 'Update: [%s] -> %s' % (vul['alert_group'].lower(), vul['affects'])
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg, refresh=self.db_choice.GetValue()))

        index = self.list.InsertItem(0, vul['alert_group'])
        self.list.SetItem(index, 1, vul['affects'])
        self.list.SetItem(index, 2, vul['details'])
        self.list.SetItem(index, 3, create_time)
        self.list.SetItemData(index, self.list.GetItemCount()+1)
        self.itemDataMap[self.list.GetItemCount()+1] = (vul['alert_group'], vul['affects'], vul['details'], "")
        self.parent_note_book.SetPageText(1, "  Results [ %s ]  " % self.list.GetItemCount())
        if conf.scanner_completed and self.result_queue.qsize() == 0:
            self.db_manager.close_db()
            self.db_manager = None

    def update_current_item(self, event):
        self.current_item = event.Index

    def populate_list(self):
        info = wx.ListItem()
        info.Mask = wx.LIST_MASK_TEXT | wx.LIST_MASK_IMAGE | wx.LIST_MASK_FORMAT
        info.Image = -1
        info.Align = 0
        info.Text = "Vulnerability"
        self.list.InsertColumn(0, info)
        info.Text = "Target"
        self.list.InsertColumn(1, info)
        info.Text = "Details"
        self.list.InsertColumn(2, info)
        info.Text = "Created"
        self.list.InsertColumn(3, info)

        self.list.SetColumnWidth(0, 250)
        self.list.SetColumnWidth(1, 250)
        self.list.SetColumnWidth(2, 150)

        self.current_item = 0

    # Used by the ColumnSorterMixin
    def GetListCtrl(self):
        return self.list

    # Used by the ColumnSorterMixin
    def GetSortImages(self):
        return self.sort_down, self.sort_up

    def get_column_text(self, index, col):
        item = self.list.GetItem(index, col)
        return item.GetText()

    def popup_menu(self, event):
        if len(self.itemDataMap) == 0:
            return
        menu = wx.Menu()
        self.copy_details = wx.MenuItem(menu, self.id_popup_copy, 'Copy details to clipboard')
        self.copy_details.SetBitmap(wx.Image(get_abs_path('ui/resource/source_code.png')).ConvertToBitmap())
        self.save_to_file = wx.MenuItem(menu, self.id_popup_dump, 'Save vulnerabilities to file')
        self.save_to_file.SetBitmap(wx.Image(get_abs_path('ui/resource/source_code.png')).ConvertToBitmap())
        self.Bind(wx.EVT_MENU, self.do_copy_details, id=self.id_popup_copy)
        self.Bind(wx.EVT_MENU, self.do_save_to_file, id=self.id_popup_dump)

        menu.Append(self.copy_details)
        menu.Append(self.save_to_file)
        self.PopupMenu(menu)
        menu.Destroy()

    def get_details(self):
        details = ''
        details += 'Name: ' + self.list.GetItem(self.current_item, 0).GetText() + '\n'
        details += 'Target: ' + self.list.GetItem(self.current_item, 1).GetText() + '\n'
        details += 'Created: ' + self.list.GetItem(self.current_item, 3).GetText() + '\n\n'
        details += 'Details: ' + self.list.GetItem(self.current_item, 2).GetText() + '\n'
        return details

    def do_copy_details(self, event):
        if len(self.itemDataMap) == 0:
            return
        if wx.TheClipboard.Open():
            wx.TheClipboard.SetData(wx.TextDataObject(self.get_details()))
            wx.TheClipboard.Close()

    def do_save_to_file(self, event):
        if len(self.itemDataMap) == 0:
            return

    def view_vulnerability_details(self, event):
        if len(self.itemDataMap) == 0:
            return
        frame = ScanResultViewFrame(self)
        frame.show_details(self.get_details())
        frame.Center(wx.BOTH)
        frame.Show()
