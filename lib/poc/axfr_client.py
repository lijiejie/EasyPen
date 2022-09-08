#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
    DNS Client to fetch zone transfer data
    Blog: http://www.lijiejie.com
    my[at]lijiejie.com
"""

import asyncio
import struct
import random


LEN_QUERY = 0    # Length of Query String


def gen_query(domain):
    TRANS_ID = random.randint(1, 65535)       # random ID
    FLAGS = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    data = struct.pack('!HHHHHH', TRANS_ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    query = b''
    for label in domain.strip().split('.'):
        query += struct.pack('!B', len(label)) + label.lower().encode()
    query += b'\x00'    # end of domain name
    data += query
    global LEN_QUERY
    LEN_QUERY = len(query)    # length of query section
    q_type = 252    # Type AXFR = 252
    q_class = 1     # CLASS IN
    data += struct.pack('!HH', q_type, q_class)
    data = struct.pack('!H', len(data)) + data    # first 2 bytes should be length
    return data


OFFSET = 0    # Response Data offset
TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 38: 'A6', 99: 'SPF'}


def decode(response):
    RCODE = struct.unpack('!H', response[2:4])[0] & 0b00001111  # last 4 bits is RCODE
    if RCODE != 0:
        return False, 'Transfer Failed. %>_<%'
    answer_rrs = struct.unpack('!H', response[6:8])[0]
    results = '<< %d records in total >>\n' % answer_rrs
    global LEN_QUERY, OFFSET
    OFFSET = 12 + LEN_QUERY + 4    # header = 12, type + class = 4
    while OFFSET < len(response):
        name_offset = response[OFFSET: OFFSET + 2]    # 2 bytes
        name_offset = struct.unpack('!H', name_offset)[0]
        if name_offset > 0b1100000000000000:
            name = get_name(response, name_offset - 0b1100000000000000, True)
        else:
            name = get_name(response, OFFSET)
        type = struct.unpack('!H', response[OFFSET: OFFSET+2] )[0]
        type = TYPES.get(type, '')
        if type != 'A':
            results += name.ljust(20).decode() + type.ljust(10) + '\n'
        """ type: 2 bytes, class: 2bytes, time to live: 4 bytes """
        OFFSET += 8
        data_length = struct.unpack('!H', response[OFFSET: OFFSET+2])[0]
        if data_length == 4 and type == 'A':
            ip = [str(num) for num in struct.unpack('!BBBB', response[OFFSET+2: OFFSET+6] ) ]
            results += name.ljust(20).decode() + type.ljust(10) + '.'.join(ip) + '\n'
        OFFSET += 2 + data_length
    return True, results


# is_pointer: an name offset or not        
def get_name(response, name_offset, is_pointer=False):
    global OFFSET
    labels = []
    while True:
        num = struct.unpack('B', bytes([response[name_offset]]))[0]
        if num == 0 or num > 128:
            break    # end with 0b00000000 or 0b1???????
        labels.append(response[name_offset + 1: name_offset + 1 + num])
        name_offset += 1 + num
        if not is_pointer:
            OFFSET += 1 + num
    name = b'.'.join(labels)
    OFFSET += 2    # 0x00
    return name
    

async def zone_transfer(server, port, domain):
    try:
        reader, writer = await asyncio.open_connection(server, port)
        data = gen_query(domain)

        writer.write(data)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), 3)

        res_len = struct.unpack('!H', data[:2])[0]    # Response Content Length
        while len(data) < res_len:
            data += reader.read(4096)
        ret = decode(data[2:])
        writer.close()
        await writer.wait_closed()
        if ret[0]:
            return ret[0], ret[1]
        return False, ''
    except Exception as e:
        return False, ''


if __name__ == '__main__':
    asyncio.run(zone_transfer('easypen-test.lijiejie.com', 53, 'vulhub.org'))
