import wx
import lib.config as conf
from lib.event import LogEvent


def get_postfix(count):
    return 's' if count > 1 else ''


def show_update_log(domain_insert_count=0, domain_update_count=0, ip_insert_count=0,
                    port_insert_count=0, port_update_count=0, refresh=None):
    msg_list = []
    if domain_insert_count != 0:
        msg_list.append('add %s domain' % domain_insert_count + get_postfix(domain_insert_count))
    if domain_update_count != 0:
        msg_list.append('update %s domain' % domain_update_count + get_postfix(domain_update_count))
    if ip_insert_count != 0:
        msg_list.append('add %s ip' % ip_insert_count + get_postfix(ip_insert_count))
    if port_insert_count != 0:
        msg_list.append('add %s port' % port_insert_count + get_postfix(port_insert_count))
    if port_update_count != 0:
        msg_list.append('update %s port' % port_update_count + get_postfix(port_update_count))

    msg = ', '.join(msg_list).capitalize()
    if msg:
        wx.PostEvent(conf.main_frame.target_tree, LogEvent(msg=msg, refresh=refresh))
