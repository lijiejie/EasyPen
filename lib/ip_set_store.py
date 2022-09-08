# IP set store
from netaddr import IPNetwork, IPAddress


class IPSetStore(object):
    def __init__(self, data_set):
        self.ip_set = set([])
        self.network_set = set([])
        self.network_iter = None
        self.clean_data(data_set)

    def clean_data(self, data_set):
        for item in data_set:
            if str(item).find('/') < 0:
                try:
                    ip = IPAddress(str(item).strip())
                    self.ip_set.add(ip)
                except Exception as e:
                    pass
            else:
                try:
                    ip = IPNetwork(str(item).strip())
                    self.network_set.add(ip)
                except Exception as e:
                    pass

    def get_ips(self, count):
        ips_to_return = []
        return_count = 0
        while True:
            if len(self.ip_set) > 0:
                ips_to_return.append(str(self.ip_set.pop()))
                return_count += 1
                if return_count >= count:  # got enough items
                    return ips_to_return
            elif self.network_iter:
                ret = next(self.network_iter, None)
                if ret is None:
                    self.network_iter = None
                else:
                    ips_to_return.append(str(ret))
                    return_count += ret.size
                    if return_count >= count:
                        return ips_to_return
            elif len(self.network_set) > 0:
                network = self.network_set.pop()
                if network.size <= 256:
                    ips_to_return.append(str(network))
                    return_count += network.size
                    if return_count >= count:
                        return ips_to_return
                else:
                    self.network_iter = network.subnet(24)
                    _network = next(self.network_iter)
                    ips_to_return.append(str(_network))
                    return_count += _network.size
                    if return_count >= count:
                        return ips_to_return
            else:
                return ips_to_return


if __name__ == '__main__':
    store = IPSetStore({'10.1.2.4', '23.40.242.10', '23.40.241.251', '10.1.2.5/20'})
    while True:
        ret = store.get_ips(1000)
        print(ret)
        if not ret:
            break
