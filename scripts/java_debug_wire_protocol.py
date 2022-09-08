#!/usr/bin/env python3
# coding=utf-8

from lib.poc.dummy import *
import struct


def p32(u):
    return struct.pack('>I', u)


def u32(p):
    return struct.unpack('>I', p)[0]


async def do_scan(ip, port, service, is_http, task_msg):
    if not port or port in [7]:
        return

    handshake = b'JDWP-Handshake'

    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(handshake)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(len(handshake)), timeout=4)
        if data != handshake:
            return

        versionCommandPack = p32(1)
        versionCommandPack += b'\x00\x01\x01'
        versionCommandPack = p32(len(versionCommandPack) + 4) + versionCommandPack
        writer.write(versionCommandPack)

        data = await asyncio.wait_for(reader.read(4), 5)
        replyLength = u32(data)
        data = await asyncio.wait_for(reader.read(replyLength), 5)
        data = data.replace(b'\x00', b'').decode('utf-8', 'ignore')
        writer.close()
        if data.find('Java Debug Wire Protocol') > 0:
            ret = {
                'alert_group': 'JDWP Connect',
                'affects': 'jdwp://{}:{}'.format(ip, port),
                'details': u'JAVA的调试接口，debug infp: {}  \n\n '
                           u'Can be exploited with https://github.com/IOActive/jdwp-shellifier'.format(data),
            }
            return ret
    except (asyncio.exceptions.TimeoutError, OSError) as e:
        pass
    except Exception as e:
        debug(e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()  # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8103, 'jdwp', True, {})
    run_plugin_test(scan)
