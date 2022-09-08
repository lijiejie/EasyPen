import logging
import pprint
import asyncio
from lib.poc_scan import PocScanner


async def test_check():
    msg = {'ip': 'easypen-test.lijiejie.com', 'port': 8080, 'service': 'http', 'is_http': True, 'policy_name': '',
           'plugin_list': []}
    s = PocScanner(msg, is_brute_scanner=False)
    r = await s.scan()
    pprint.pprint(r)


if __name__ == '__main__':
    logger = logging.getLogger("port_crack")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    # add ch to logger
    logger.addHandler(ch)
    loop = asyncio.get_event_loop()
    task = loop.create_task(test_check())
    loop.run_until_complete(task)
