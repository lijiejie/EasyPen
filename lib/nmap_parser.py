# -*- encoding:utf-8 -*-

from lxml import etree
import os
import sys
from io import BytesIO

cwd = os.path.split(__file__)[0]
sys.path.insert(0, os.path.join(cwd, '../..'))


class Host(object):
    def __init__(self):
        self.status = 'down'
        self.ipv4_addr = ''
        self.host_on = True
        self.os_name = ''
        self.hostname = ''
        self.ports = []


class Port(object):
    def __init__(self):
        self.port_id = ''
        self.service_name = ''
        self.service_product = ''
        self.service_version = ''
        self.is_http = False

    def to_dict(self):
        d = {'port_id': self.port_id,
             'service_name': self.service_name,
             'service_product': self.service_product,
             'service_version': self.service_version,
             'is_http': self.is_http,
             }
        return d


def correct_xml(file_path):
    xml = BytesIO()
    with open(file_path, 'r') as f:
        xml_info = f.read()
        end_index = xml_info.find('</nmaprun>') + len('</nmaprun>')
        xml.write(xml_info[:end_index].encode())
        xml.seek(0)
    return xml


def parse_nmap_output(file_path):
    try:
        xml_doc = etree.parse(correct_xml(file_path))
        xml_root = xml_doc.getroot()
        hosts = []

        num_services = int(xml_root.find('scaninfo').get('numservices', 0))

        for host in xml_root.findall('host'):
            obj_host = Host()
            if host.find('status') is not None:
                host_state = host.find('status').get('state')
            else:
                host_state = ''

            if host_state == 'up':
                obj_host.status = 'up'

            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    obj_host.ipv4_addr = address.get('addr')  # IP

            for hostname in host.find('hostnames').findall('hostname'):
                if hostname.get('type') == 'user':
                    obj_host.hostname = hostname.get('name')

            if not host.find('ports') is None:
                for port in host.find('ports').findall('port'):
                    if port.get('protocol') == 'tcp':  # TCP only
                        obj_port = Port()
                        obj_port.port_state = port.find('state').get('state') if port.find('state') is not None else ''
                        if obj_port.port_state != 'open':
                            continue

                        obj_port.port_id = int(port.get('portid'))

                        if not port.find('service') is None:
                            obj_port.service_name = port.find('service').get('name')
                            if obj_port.service_name == 'unknown' \
                                    and port.find('service').get('servicefp', '').find('Content-Type:\\x20') > 0 \
                                    and port.find('service').get('servicefp', '').find('Content-Length:\\x20') > 0:
                                obj_port.service_name = 'http-like'
                            if port.find('service').get('product'):  # can be None
                                obj_port.service_product = port.find('service').get('product')
                            if port.find('service').get('version'):
                                obj_port.service_version = port.find('service').get('version')
                        else:
                            obj_port.service_name = 'unknown'
                            obj_port.service_product = obj_port.service_version = ''

                        for script in port.findall('script'):
                            if script.get('id') == 'is-http':
                                obj_port.is_http = True

                        obj_host.ports.append(obj_port.to_dict())

            if num_services > 100 and obj_host.ports:
                if len(obj_host.ports) > num_services / 2:    # 过半的端口开放
                    obj_host.ports = []
                    print('[Too many ports found] %s, scan %s services, %s open' %
                          (obj_host.ipv4_addr, num_services, len(obj_host.ports)))

            elif obj_host.ports and len(obj_host.ports) > 20:   # remove all unknown ports
                for port in obj_host.ports[:]:
                    if port.get('service_name', 'unknown') == 'unknown':
                        obj_host.ports.remove(port)

            if host.find('os') is not None:
                for _os in host.find('os').findall('osmatch'):
                    obj_host.os_name = _os.get('name')
                    break

            hosts.append(obj_host)
        return hosts
    except Exception as e:
        print('parse_nmap_output.exception: %s' % str(e))
        return []


if __name__ == '__main__':
    hosts = parse_nmap_output(r'..\tools\nmap\port_scan_output_1651670201.xml')

    for h in hosts:
        if h.host_on:
            print(h.ipv4_addr, h.hostname)
            print('OS: %s' % h.os_name)
            for p in h.ports:
                print(p['port_id'], p['service_name'], p['service_product'], p['service_version'], p['is_http'])
