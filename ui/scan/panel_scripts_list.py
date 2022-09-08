#!/usr/bin/env python

import wx
from lib.common import get_all_scripts, get_abs_path
import wx.lib.mixins.listctrl as list_mix
from ui.scan.frame_soure_code_viewer import SourceCodeViewFrame
import lib.config as conf


class ScriptListCtrl(wx.ListCtrl, list_mix.ListCtrlAutoWidthMixin):
    def __init__(self, parent, pos=wx.DefaultPosition, size=wx.DefaultSize, style=0):
        wx.ListCtrl.__init__(self, parent, -1, pos, size, style)
        list_mix.ListCtrlAutoWidthMixin.__init__(self)


class ScriptListCtrlPanel(wx.Panel, list_mix.ColumnSorterMixin):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.WANTS_CHARS)
        # image list
        self.image_list = wx.ImageList(16, 16)
        self.img_0 = self.image_list.Add(wx.Image(get_abs_path("ui/resource/script_file.png")).ConvertToBitmap())
        self.sort_up = self.image_list.Add(wx.Image(get_abs_path("ui/resource/sort_up.png")).ConvertToBitmap())
        self.sort_down = self.image_list.Add(wx.Image(get_abs_path("ui/resource/sort_down.png")).ConvertToBitmap())
        self.list = ScriptListCtrl(self, style=wx.LC_REPORT | wx.BORDER_SUNKEN | wx.LC_SORT_ASCENDING)
        self.list.SetImageList(self.image_list, wx.IMAGE_LIST_SMALL)

        self.btn_check_all = wx.Button(self, -1, "Check All")
        self.btn_check_all.Bind(wx.EVT_BUTTON, self.check_all_boxes)
        self.btn_uncheck_all = wx.Button(self, -1, "Uncheck All")
        self.btn_uncheck_all.Bind(wx.EVT_BUTTON, self.uncheck_all_boxes)
        self.btn_reload_scripts = wx.Button(self, -1, "Reload Scripts")
        self.btn_reload_scripts.Bind(wx.EVT_BUTTON, self.reload_scripts)
        self.lbl_selected = wx.StaticText(self, -1, "")
        self.lbl_selected.SetForegroundColour((100, 100, 100))
        self.keyword = wx.SearchCtrl(self, style=wx.TE_PROCESS_ENTER, size=(160, -1))
        self.keyword.ShowCancelButton(True)
        self.keyword.Bind(wx.EVT_SEARCH, self.do_search)
        self.keyword.Bind(wx.EVT_CHAR_HOOK, self.do_empty_enter)
        self.keyword.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN, self.clear_keyword)
        self.select_buttons_sizer = select_buttons_sizer = wx.BoxSizer(wx.HORIZONTAL)
        select_buttons_sizer.Add(self.btn_check_all, 1, wx.TOP | wx.RIGHT, 10)
        select_buttons_sizer.Add(self.btn_uncheck_all, 1, wx.ALL, 10)
        select_buttons_sizer.Add(self.btn_reload_scripts, 1, wx.ALL, 10)
        select_buttons_sizer.Add((10, 10), wx.EXPAND, 10)
        select_buttons_sizer.Add(self.lbl_selected, 1, wx.TOP | wx.RIGHT, 15)
        select_buttons_sizer.Add(self.keyword, 1, wx.TOP, 10)

        self.chk_info_dis = wx.CheckBox(self, -1, "Scan Information Disclosure Vulnerabilities for HTTP targets")
        self.chk_info_dis.Enable(False)   # not yet implemented

        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.list, 1, wx.EXPAND)
        sizer.Add(select_buttons_sizer)
        sizer.Add(self.chk_info_dis)
        self.list.EnableCheckBoxes(enable=True)
        self.itemDataMap = get_all_scripts()
        self.populate_list()
        self.check_all_boxes(None)
        self.update_check_count(None)
        list_mix.ColumnSorterMixin.__init__(self, 3)
        self.SortListItems(2, False)

        self.SetSizer(sizer)
        self.SetAutoLayout(True)

        self.list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.update_current_item)
        self.list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.update_current_item)
        self.list.Bind(wx.EVT_LIST_ITEM_FOCUSED, self.update_current_item)

        self.list.Bind(wx.EVT_LIST_ITEM_CHECKED, self.update_check_count)
        self.list.Bind(wx.EVT_LIST_ITEM_UNCHECKED, self.update_check_count)

        self.list.Bind(wx.EVT_LEFT_DCLICK, self.double_click_select)

        self.list.Bind(wx.EVT_COMMAND_RIGHT_CLICK, self.popup_menu)    # for wxMSW
        self.list.Bind(wx.EVT_RIGHT_UP, self.popup_menu)    # for wxGTK
        self.current_item = None
        self.id_view_source = wx.NewIdRef()

    def update_current_item(self, event):
        self.current_item = event.Index

    def reload_scripts(self, event):
        self.keyword.SetValue('')
        self.list.ClearAll()
        self.itemDataMap = get_all_scripts()
        self.populate_list()
        self.update_check_count(None)

    def clear_keyword(self, event):
        self.keyword.SetValue('')
        self.do_search(event)

    def do_search(self, event):
        keyword = self.keyword.GetValue().strip() if self.keyword.GetValue() else ''
        self.list.ClearAll()
        self.itemDataMap = get_all_scripts(keyword)
        self.populate_list()
        self.check_all_boxes(None)
        self.update_check_count(None)

    def do_empty_enter(self, event):
        if hasattr(event, "KeyCode"):
            if event.KeyCode == 13 and not self.keyword.GetValue():
                self.do_search(None)
        event.Skip()

    def populate_list(self):
        info = wx.ListItem()
        info.Mask = wx.LIST_MASK_TEXT | wx.LIST_MASK_IMAGE | wx.LIST_MASK_FORMAT
        info.Image = -1
        info.Align = 0
        info.Text = "Script"
        self.list.InsertColumn(0, info)
        info.Text = "Description"
        self.list.InsertColumn(1, info)
        info.Text = "Updated"
        self.list.InsertColumn(2, info)

        for key, data in self.itemDataMap.items():
            index = self.list.InsertItem(self.list.GetItemCount(), data[0])
            self.list.SetItem(index, 1, data[1])
            self.list.SetItem(index, 2, data[3])
            self.list.SetItemData(index, key)

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

    def update_check_count(self, event):
        total = self.list.GetItemCount()
        checked = [i for i in range(total) if self.list.IsItemChecked(item=i)]
        self.lbl_selected.SetLabelText('%s of %s selected' % (len(checked), total))
        self.select_buttons_sizer.Layout()
        # self.current_item = 0

    def check_all_boxes(self, event):
        count = self.list.GetItemCount()
        for i in range(count):
            self.list.CheckItem(item=i, check=True)

    def uncheck_all_boxes(self, event):
        count = self.list.GetItemCount()
        for i in range(count):
            self.list.CheckItem(item=i, check=False)

    def get_checked_items(self):
        count = self.list.GetItemCount()
        checked = [self.list.GetItem(i).Text for i in range(count) if self.list.IsItemChecked(item=i)]
        if not checked:
            conf.user_selected_plugins = None    # no items checked
            return
        all_scripts = []
        for name in get_all_scripts():
            all_scripts.append(name)
        if len(checked) == len(all_scripts):
            conf.user_selected_plugins = []    # all items checked, pass empty array instead
        else:
            conf.user_selected_plugins = checked
        return len(checked)

    def popup_menu(self, event):
        if len(self.itemDataMap) < 1:
            return
        menu = wx.Menu()
        self.view_source = wx.MenuItem(menu, self.id_view_source, 'View Source Code')
        self.view_source.SetBitmap(wx.Image(get_abs_path('ui/resource/source_code.png')).ConvertToBitmap())
        self.Bind(wx.EVT_MENU, self.view_source_code, id=self.id_view_source)

        menu.Append(self.view_source)
        self.PopupMenu(menu)
        menu.Destroy()

    def view_source_code(self, event):
        if len(self.itemDataMap) < 1:
            return
        item = self.list.GetItem(self.current_item)
        script_name = item.Text
        frame = SourceCodeViewFrame(self)
        frame.show_source_code(script_name)
        frame.Center(wx.BOTH)
        frame.Show()

    def double_click_select(self, event):
        if len(self.itemDataMap) < 1:
            return
        val = not self.list.IsItemChecked(self.current_item)
        self.list.CheckItem(self.current_item, val)


if __name__ == '__main__':
    app = wx.App()
    app.SetAppName('Test')
    conf.load_config()
    frame = wx.Frame(None, -1, "Test", size=(900, 700))
    win = ScriptListCtrlPanel(frame)
    frame.Show()
    frame.Center(wx.BOTH)
    app.MainLoop()
