#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.poc.dummy import *
import struct


async def validate(ip, port, username, password):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b'\x05\x01\x02')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(200), 5)

        if data != b'\x05\x02':
            return False
        payload = struct.pack('!BB' + str(len(username)) +
                              'sB' + str(len(password)) + 's', 1,
                              len(username), username,
                              len(password), password)
        writer.write(payload)
        data = await asyncio.wait_for(reader.read(200), 5)
        if data == b'\x01\x00':  # success
            details = 'Socks5 Weak Password %s:%s %s / %s' % (ip, port, username.decode(), password.decode())
            ret = {
                'alert_group': 'Socks5 Proxy',
                'affects': 'socks5://%s:%s' % (ip, port),
                'details': details
            }
            return ret

    except Exception as e:
        debug(e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass


async def do_scan(ip, port, service, is_http, task_msg):
    if service.lower() not in ['unknown', 'socks', 'socks5']:
        return

    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(b'\x05\x02\x00\x02')
        await writer.drain()
        data = await asyncio.wait_for(reader.read(200), 5)
        writer.close()
        try:
            await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass

        if data[0].to_bytes(1, byteorder='big') != b'\x05':  # 不是socks5代理
            return
        if data[1].to_bytes(1, byteorder='big') == b'\x00':  # 匿名代理
            details = 'Socks5 Proxy[No Auth] %s:%s' % (ip, port)
            ret = {
                'alert_group': 'Socks5 Proxy',
                'affects': 'socks5://%s:%s' % (ip, port),
                'details': details
            }
            return ret
        elif data[1].to_bytes(1, byteorder='big') == b'\x02':  # 用户密码验证
            auths = [b'admin:123456', b'admin:admin', b'root:root']

            for auth in auths:
                username, password = auth.split(b":")
                ret = await validate(ip, port, username, password)
                if ret:
                    return ret
    except (IndexError, asyncio.exceptions.TimeoutError, OSError) as e:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 33060, 'socks', False, {})
    run_plugin_test(scan)
