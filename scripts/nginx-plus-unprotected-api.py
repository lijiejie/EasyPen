from lib.poc.dummy import *
import json


@http_scan
async def do_scan(ip, port, service, is_http, task_msg):
    base_url = '{}://{}:{}'.format(service, ip, port)

    try:
        for path in ['/api/6/nginx', '/api/5/nginx', '/api/4/nginx', '/api/3/nginx']:

            r = await http_client(ip, port).get(base_url + path, headers={'Referer': base_url}, timeout=20)

            if r.status_code == 200 and r.headers.get('Content-Type', '').startswith('application/json') and \
                    r.text.startswith('{"version":') and '"build":"nginx-plus' in r.text and 'load_timestamp' in r.text:

                url2 = base_url + path.replace('/nginx', '/http/upstreams/a/servers/')
                data = json.dumps({'a': '1'})

                r = await http_client(ip, port).post(url2, data=data, headers={'Referer': base_url}, timeout=20)

                if r.text.startswith('{"error":{"status":405,"text":"method disabled","code":"MethodDisabled"}'):
                    ret = {
                        'alert_group': 'nginx-plus-unprotected-api-read-only',
                        'affects': '{}://{}:{}'.format(service, ip, port),
                        'details': '{}\n{}\nNGINX+ unprotected API interface'.format(url2, r.text)
                    }
                elif r.text.startswith(
                        '{"error":{"status":400,"text":"unknown parameter \\"a\\"","code":"UpstreamConfFormatError"}'):
                    ret = {
                        'alert_group': 'nginx-plus-unprotected-api-read-write',
                        'affects': base_url,
                        'details': '{}\n{}\nNGINX+ unprotected API interface'.format(url2, r.text)
                    }
                else:
                    ret = {
                        'alert_group': 'nginx+ API on',
                        'affects': '{}://{}:{}'.format(service, ip, port),
                        'details': '{}\nnginx+ API on'.format(base_url + path)
                    }
                return ret
    except Exception as e:
        debug(e)


if __name__ == '__main__':
    scan = do_scan('easypen-test.lijiejie.com', 80, 'http', True, task_msg={})
    run_plugin_test(scan)

