import wx
import shutil
import os
from wx.lib.mixins.treemixin import ExpansionState
from wx.lib.agw.customtreectrl import CustomTreeCtrl
import lib.config as conf
from lib.common import get_abs_path, show_progress_bar, hide_progress_bar, log_output
from lib.database import create_database, get_db_statistics
from lib.event import Log_EVT_BINDER


class TargetsFilter(wx.SearchCtrl):
    def __init__(self, parent):
        wx.SearchCtrl.__init__(self, parent, style=wx.TE_PROCESS_ENTER)
        self.ShowCancelButton(True)
        self.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN, lambda e: self.SetValue(''))

        if 'gtk3' in wx.PlatformInfo:
            txt = wx.TextCtrl(parent)
            bs = txt.GetBestSize()
            txt.DestroyLater()
            self.SetMinSize((-1, bs.height + 4))


class TargetsTree(ExpansionState, CustomTreeCtrl):
    def __init__(self, parent, target_filter):
        self.target_filter = target_filter
        CustomTreeCtrl.__init__(self, parent, style=wx.TR_DEFAULT_STYLE | wx.TR_HAS_VARIABLE_ROW_HEIGHT)
        self.root_node = None
        self.build_tree_image_list()
        self.SetSpacing(10)
        self.SetWindowStyle(self.GetWindowStyle() & ~wx.TR_LINES_AT_ROOT)
        self.SetInitialSize((100, 80))
        self.Bind(Log_EVT_BINDER, self.process_log_event)

    def process_log_event(self, event):
        if hasattr(event, 'msg'):
            log_output(event.msg)
        if hasattr(event, 'refresh'):
            self.update_by_db_name(event.refresh)
        if hasattr(event, 'start_timer'):
            if hasattr(event, 'interval'):
                show_progress_bar(int(event.interval))
            else:
                show_progress_bar()
        if hasattr(event, 'stop_timeer'):
            hide_progress_bar()

    def AppendItem(self, parent, text, image=-1, wnd=None):
        # item = CustomTreeCtrl.AppendItem(self, parent, text, image=image, ct_type=1, wnd=wnd)
        item = CustomTreeCtrl.AppendItem(self, parent, text, image=image, wnd=wnd)
        return item

    def build_tree_image_list(self):
        img_list = wx.ImageList(16, 16)
        img_list.Add(wx.Image(get_abs_path("ui/resource/database.png")).ConvertToBitmap())
        for i in range(7):
            img_list.Add(wx.Image(get_abs_path("ui/resource/target_%s.png" % i)).ConvertToBitmap())
        self.AssignImageList(img_list)

    def GetItemIdentity(self, item):
        return self.GetItemData(item)

    def recreate_tree(self, evt=None):
        expansion_state = list(range(len(conf.target_tree_list)+1))[:4]

        current = None
        item = self.GetSelection()
        if item:
            parent = self.GetItemParent(item)
            if parent:
                current = (self.GetItemText(item), self.GetItemText(parent))

        self.Freeze()
        self.DeleteAllItems()
        self.root_node = self.AddRoot("Target Database")
        self.SetItemImage(self.root_node, 0)
        self.SetItemData(self.root_node, 0)

        tree_font = self.GetFont()
        category_font = self.GetFont()
        item_font = self.GetFont()

        tree_font.SetPointSize(tree_font.GetPointSize()+1)
        # tree_font.MakeBold()
        category_font.SetPointSize(category_font.GetPointSize()+1)
        self.SetItemFont(self.root_node, tree_font)

        first_child = None
        selected_item = None
        target_filter = self.target_filter.GetValue()
        count = 0

        for category, items in conf.target_tree_list:
            count += 1
            if target_filter:
                items = items if target_filter.lower() in category.lower() else []
            if items:
                category_child = self.AppendItem(self.root_node, category, image=count % 7 + 1)
                self.SetItemFont(category_child, category_font)
                self.SetItemData(category_child, count)
                if not first_child:
                    first_child = category_child
                for item in items:
                    child_item = self.AppendItem(category_child, item)
                    self.SetItemFont(child_item, item_font)
                    self.SetItemData(child_item, count)
                    if current and (item, category) == current:
                        selected_item = child_item

        self.Expand(self.root_node)
        if first_child:
            self.Expand(first_child)
        if target_filter:
            self.ExpandAll()
        elif expansion_state:
            self.SetExpansionState(expansion_state)
        if selected_item:
            self.SelectItem(selected_item)

        self.Thaw()

    def update_by_db_name(self, db_name):
        target_item = self.FindItem(self.root_node, db_name)
        if not target_item:
            return
        ret = get_db_statistics(db_name)
        if not ret:
            return
        domain_item, cookie = self.GetFirstChild(target_item)
        self.SetItemText(domain_item, 'Domain (%s)' % ret.get('domain'))
        ip_item, cookie = self.GetNextChild(target_item, cookie)
        self.SetItemText(ip_item, 'IP (%s)' % ret.get('ip', 0))
        port_item, cookie = self.GetNextChild(target_item, cookie)
        self.SetItemText(port_item, 'Port (%s)' % ret.get('port', 0))
        vul_item, cookie = self.GetNextChild(target_item, cookie)
        self.SetItemText(vul_item, 'Vulnerability (%s)' % ret.get('vulnerability', 0))
        url_item, cookie = self.GetNextChild(target_item, cookie)
        self.SetItemText(url_item, 'URL (%s)' % ret.get('url', 0))


class TargetDatabasePanel(wx.Panel):
    def __init__(self, parent, frame):
        self.frame = frame
        self.discover_panel = frame.discover_panel
        self.db_panel = frame.db_panel
        wx.Panel.__init__(self, parent, -1, style=wx.TAB_TRAVERSAL | wx.CLIP_CHILDREN)
        self.target_filter = TargetsFilter(self)
        self.target_tree = TargetsTree(self, self.target_filter)
        self.Bind(wx.EVT_TEXT, self.target_tree.recreate_tree, source=self.target_filter)
        self.target_tree.recreate_tree()
        expansion_state = list(range(len(conf.target_tree_list)+1))[:4]
        self.target_tree.SetExpansionState(expansion_state)
        self.target_tree.SelectItem(self.target_tree.root_node)
        self.target_tree.Bind(wx.EVT_TREE_SEL_CHANGED, self.on_tree_sel_changed)
        self.target_tree.Bind(wx.EVT_LEFT_DCLICK, self.on_tree_left_dbclick)

        add_db_button = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        add_db_button.SetToolTip("Create new database")
        add_db_button.SetBitmap(wx.Image('ui/resource/add_target.png').ConvertToBitmap())
        delete_button = wx.Button(self, -1, "", size=(24, 24), style=wx.NO_BORDER)
        delete_button.SetToolTip("Delete selected database")
        delete_button.SetBitmap(wx.Image('ui/resource/delete-target.png').ConvertToBitmap())
        button_box = wx.BoxSizer(wx.HORIZONTAL)
        button_box.Add(add_db_button, 0, wx.EXPAND | wx.ALL, border=2)
        button_box.Add(delete_button, 0, wx.EXPAND | wx.ALL, border=2)
        button_box.Add(self.target_filter, 1, wx.EXPAND | wx.ALL, border=2)
        self.Bind(wx.EVT_BUTTON, self.add_target, add_db_button)
        self.Bind(wx.EVT_BUTTON, self.delete_target, delete_button)
        left_box = wx.BoxSizer(wx.VERTICAL)
        left_box.Add(button_box, 0, wx.EXPAND | wx.ALL, 5)
        left_box.Add(self.target_tree, 1, wx.EXPAND)

        if 'wxMac' in wx.PlatformInfo:
            left_box.Add((5, 5))
        self.SetSizer(left_box)

    def on_tree_sel_changed(self, event):
        event.Skip()

    def on_tree_left_dbclick(self, event):
        item = self.target_tree.GetSelection()
        parent = self.target_tree.GetItemParent(item)
        if not item or item == self.target_tree.root_node or parent == self.target_tree.root_node:
            pass
        else:
            db_name = self.target_tree.GetItemText(parent)
            table_name = self.target_tree.GetItemText(item).strip().replace('(', ' ').split()[0]
            self.db_panel.cbo_databases.SetValue(db_name)
            if table_name in ["Port", "Domain", "IP", "Vulnerability"]:
                self.db_panel.keyword.SetValue('')
                self.db_panel.cbo_table.SetValue(table_name)
                self.db_panel.do_search(None)
            conf.main_frame.notebook.SetSelection(1)
        event.Skip()

    def add_target(self, evt):
        dlg = wx.TextEntryDialog(self, 'Enter database name\nShould be less than 12 characters', 'Create Database', '')
        dlg.SetMaxLength(12)

        if dlg.ShowModal() == wx.ID_OK:
            target = dlg.GetValue().strip()
            is_valid = True
            if not target:
                is_valid = False
                wx.MessageBox('Target name can not be empty', 'ERROR', wx.ICON_WARNING)
            for c in r'\/:*?"<>|':
                if c in target:
                    is_valid = False
                    wx.MessageBox('Invalid target name', 'ERROR', wx.ICON_WARNING)
            if target.lower() in [x[0].lower() for x in conf.target_tree_list]:
                is_valid = False
                wx.MessageBox('Target existed, try another name', 'ERROR', wx.ICON_WARNING)
            if is_valid:
                create_database(target)
                conf.target_tree_list.insert(
                    0,
                    (target, ['Domain (0)', 'IP (0)', 'Port (0)', 'Vulnerability (0)', 'URL (0)'])
                )
                self.target_tree.recreate_tree()
                self.discover_panel.add_target(target)
                self.db_panel.refresh_cbo_databases()
                self.frame.scan_panel.scan_box.refresh_cbo_databases()
                log_output('Add new target: %s' % target)

        dlg.Destroy()

    def delete_target(self, evt):
        search_name = []
        item = self.target_tree.GetSelection()
        if not item or item == self.target_tree.root_node:
            wx.MessageBox('No target chosen', 'EasyPen', wx.ICON_WARNING)
            return
        search_name.append(self.target_tree.GetItemText(item))
        parent = self.target_tree.GetItemParent(item)
        if parent:
            search_name.append(self.target_tree.GetItemText(parent))
        for name in search_name:
            if os.path.exists(os.path.join(conf.root_path, 'database/%s' % name)):
                dlg = wx.MessageDialog(self,
                                       'About to delete database [%s]\n'
                                       'Data can not be recovered, continue?' % name, 'Delete Database',
                                       wx.YES_NO | wx.ICON_WARNING)
                if dlg.ShowModal() == wx.ID_YES:
                    try:
                        shutil.rmtree(os.path.join(conf.root_path, 'database/%s' % name))
                    except Exception as e:
                        wx.MessageBox("Database delete failed:\n" + str(e), "EasyPen", wx.ICON_ERROR)
                        log_output('Delete target [%s] failed' % name)
                        return
                    log_output('Database [%s] deleted' % name)
                    for item in conf.target_tree_list:
                        if item[0] == name:
                            conf.target_tree_list.remove(item)
                    self.target_tree.recreate_tree()
                    self.discover_panel.refresh_cbo_databases()
                    self.db_panel.refresh_cbo_databases()
                    self.frame.scan_panel.scan_box.refresh_cbo_databases()
