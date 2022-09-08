# -*- encoding:utf-8 -*-
# subprocess with timeout

import asyncio
import time
import logging
import signal
import psutil
import lib.config as conf

logger = logging.getLogger("port_crack")
logger.setLevel(logging.INFO)


def kill_child_processes(parent_pid, sig=signal.SIGTERM):
    try:
        parent = psutil.Process(parent_pid)
    except psutil.NoSuchProcess as e:
        return
    children = parent.children(recursive=True)
    for process in children:
        process.send_signal(sig)


async def check_cmd_output(cmd, timeout, shell=True):
    try:
        p = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        start_time = time.time()
        while p.returncode is None:
            kill_process = False
            if time.time() - start_time > timeout:
                kill_process = True
                logger.info('[ERROR] Kill timed out process: %s' % cmd)
            elif conf.scan_aborted:
                kill_process = True
                logger.info('[Info] User aborted scan, kill process: %s' % cmd)

            if kill_process:
                try:
                    if shell:
                        kill_child_processes(p.pid)
                    p.terminate()
                    break
                except Exception as e:
                    pass
            else:
                await asyncio.sleep(0.2)
        ret = await p.communicate()
        return ret[0].decode()
    except Exception as e:
        logger.error('[check_cmd_output.exception]: %s' % str(e))


if __name__ == '__main__':
    task = check_cmd_output('ping www.baidu.com -n 10000', 5, True)
    asyncio.get_event_loop()
    asyncio.run(task)

