import wx
import shutil
import os
from wx.lib.agw.customtreectrl import CustomTreeCtrl
import wx.lib.agw.customtreectrl as CT
import lib.config as conf
from lib.common import get_abs_path
from lib.database import get_db_statistics
from ui.settings.settings_ui.panel_discover_options import DiscoverOptionsPanel
from ui.settings.settings_ui.panel_scanner_options import ScannerOptionsPanel
from ui.settings.settings_ui.panel_ports_profile import PortsProfilePanel


class OptionTree(CustomTreeCtrl):
    def __init__(self, parent):
        CustomTreeCtrl.__init__(self, parent,
                                agwStyle=CT.TR_HAS_VARIABLE_ROW_HEIGHT | CT.TR_HIDE_ROOT | CT.TR_NO_LINES |
                                         CT.TR_NO_BUTTONS | CT.TR_FULL_ROW_HIGHLIGHT)
        self.SetBackgroundColour(wx.WHITE)
        self.root_node = None
        self.build_tree_image_list()
        self.SetSpacing(5)
        self.SetInitialSize((100, 100))
        self.menu = None
        self.Bind(wx.EVT_CONTEXT_MENU, self.on_context_menu)
        self.first_item = None
        self.SetCursor(wx.Cursor(wx.CURSOR_HAND))

    def on_context_menu(self, event):
        if not self.menu:
            self.id_send_to_scanner = wx.NewIdRef()
            self.Bind(wx.EVT_MENU, self.on_send_click, id=self.id_send_to_scanner)
        menu = wx.Menu()
        item = wx.MenuItem(menu, self.id_send_to_scanner, "Send To Scanner")
        menu.Append(item)
        self.PopupMenu(menu)
        menu.Destroy()

    def on_send_click(self, event):
        pass

    def AppendItem(self, parent, text, image=-1, wnd=None):
        # item = CustomTreeCtrl.AppendItem(self, parent, text, image=image, ct_type=1, wnd=wnd)
        item = CustomTreeCtrl.AppendItem(self, parent, text, image=image, wnd=wnd)
        return item

    def build_tree_image_list(self):
        img_list = wx.ImageList(16, 16)
        img_list.Add(wx.Image(get_abs_path("ui/resource/settings_general.png")).ConvertToBitmap())
        img_list.Add(wx.Image(get_abs_path("ui/resource/settings_discover_options.png")).ConvertToBitmap())
        img_list.Add(wx.Image(get_abs_path("ui/resource/settings_scan_options.png")).ConvertToBitmap())
        img_list.Add(wx.Image(get_abs_path("ui/resource/settings_port.png")).ConvertToBitmap())
        self.AssignImageList(img_list)

    def GetItemIdentity(self, item):
        return self.GetItemData(item)

    def recreate_tree(self, evt=None):

        current = None
        item = self.GetSelection()
        if item:
            parent = self.GetItemParent(item)
            if parent:
                current = (self.GetItemText(item), self.GetItemText(parent))

        self.Freeze()
        self.DeleteAllItems()
        self.root_node = self.AddRoot("Settings")

        tree_font = self.GetFont()
        category_font = self.GetFont()
        tree_font.SetPointSize(tree_font.GetPointSize()+1)
        self.SetItemFont(self.root_node, tree_font)

        self.first_item = category_child = self.AppendItem(self.root_node, 'General', image=0)
        self.SetItemFont(category_child, category_font)
        self.SetItemData(category_child, 1)

        category_child = self.AppendItem(self.root_node, 'Discover Options', image=1)
        self.SetItemFont(category_child, category_font)
        self.SetItemData(category_child, 1)

        category_child = self.AppendItem(self.root_node, 'Scanner Options', image=2)
        self.SetItemFont(category_child, category_font)
        self.SetItemData(category_child, 1)

        category_child = self.AppendItem(self.root_node, 'Port Scan Profiles', image=3)
        self.SetItemFont(category_child, category_font)
        self.SetItemData(category_child, 2)
        self.Thaw()


class OptionTreePanel(wx.Panel):
    def __init__(self, parent):
        wx.Panel.__init__(self, parent, -1, style=wx.TAB_TRAVERSAL | wx.SIMPLE_BORDER, size=(200, -1))
        self.settings_panel = parent
        self.option_tree = OptionTree(self)
        self.Bind(wx.EVT_TEXT, self.option_tree.recreate_tree)
        self.option_tree.recreate_tree()
        self.option_tree.SelectItem(self.option_tree.first_item)
        self.option_tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.on_tree_sel_changed)
        self.option_tree.Bind(wx.EVT_LEFT_DCLICK, self.on_tree_left_dbclick)

        left_box = wx.BoxSizer(wx.VERTICAL)
        left_box.Add(self.option_tree, 0, wx.EXPAND, 5)
        left_box.Add((-1, 10), 1, wx.EXPAND, 5)

        if 'wxMac' in wx.PlatformInfo:
            left_box.Add((5, 5))
        self.SetSizer(left_box)

    def on_tree_sel_changed(self, event):
        txt = self.option_tree.GetItemText(self.option_tree.GetSelection())
        right_panel = self.settings_panel.right_panel
        if txt == right_panel.current_panel_name:
            return
        else:
            right_panel.Freeze()
            right_panel.current_panel_name = txt
            if txt not in right_panel.panel_list:
                new_panel = None
                if txt == 'Discover Options':
                    new_panel = DiscoverOptionsPanel(right_panel)
                if txt == 'Scanner Options':
                    new_panel = ScannerOptionsPanel(right_panel)
                elif txt == 'Port Scan Profiles':
                    new_panel = PortsProfilePanel(right_panel)
                right_panel.panel_list[txt] = new_panel

            right_panel.current_panel.Hide()
            right_panel.sizer.Detach(right_panel.current_panel)
            right_panel.current_panel = right_panel.panel_list[txt]
            right_panel.current_panel_name = txt
            right_panel.current_panel.Show()
            right_panel.sizer.Add(right_panel.current_panel, 1, wx.EXPAND)

            right_panel.Thaw()
            self.settings_panel.Layout()
            right_panel.Layout()

    def on_tree_left_dbclick(self, event):
        item = self.option_tree.GetSelection()
        parent = self.option_tree.GetItemParent(item)
        if not item or item == self.option_tree.root_node or parent == self.option_tree.root_node:
            pass
        else:
            db_name = self.option_tree.GetItemText(parent)
            table_name = self.option_tree.GetItemText(item).strip().replace('(', ' ').split()[0]
        event.Skip()
