import yaml
import flag
import socket
import maxminddb
from tqdm import tqdm
import threading

thread_max_num = threading.Semaphore(50)  

ss_supported_ciphers = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'rc4-md5', 'chacha20', 'chacha20-ietf', 'xchacha20', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305']
ssr_supported_obfs = ['plain', 'http_simple', 'http_post', 'random_head', 'tls1.2_ticket_auth', 'tls1.2_ticket_fastauth']
ssr_supported_protocol = ['origin', 'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b']
vmess_supported_ciphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none']

def push_parse(bar,clash,countrify,info,iplist,passlist):
    count = 1
    ss_omit_ip_dupe = 0
    ss_omit_cipher_unsupported = 0
    with thread_max_num:
        def start_push_parse(info):
            x = info
            authentication = ''
            x['port'] = int(x['port'])
            try:
                ip = str(socket.gethostbyname(x["server"]))
            except:
                ip = x['server']
            try:
                country = str(countrify.get(ip)['country']['iso_code'])
            except:
                country = 'UN'
            if x['type'] == 'ss':
                try:
                    if x['cipher'] not in ss_supported_ciphers:
                        ss_omit_cipher_unsupported = ss_omit_cipher_unsupported + 1
                        pass
                    #if country != 'CN':
                    #    if ip in iplist:
                    #        ss_omit_ip_dupe = ss_omit_ip_dupe + 1
                    #        pass
                    #    else:
                    #        iplist[ip] = []
                    #        iplist[ip].append(x['port'])
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SSS'
                    authentication = 'password'
                except:
                    pass
            elif x['type'] == 'ssr':
                try:
                    if x['cipher'] not in ss_supported_ciphers:
                        pass
                    if x['obfs'] not in ssr_supported_obfs:
                        pass
                    if x['protocol'] not in ssr_supported_protocol:
                        pass
                    #if country != 'CN':
                    #    if ip in iplist:
                    #        pass
                    #    else:
                    #        iplist.append(ip)
                    #        iplist[ip].append(x['port'])
                    authentication = 'password'
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SSR'
                except:
                    pass
            elif x['type'] == 'vmess':
                try:
                    if 'udp' in x:
                        if x['udp'] not in [False, True]:
                            pass
                    if 'tls' in x:
                        if x['tls'] not in [False, True]:
                            pass
                    if 'skip-cert-verify' in x:
                        if x['skip-cert-verify'] not in [False, True]:
                            pass
                    if x['cipher'] not in vmess_supported_ciphers:
                        pass
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'VMS'
                    authentication = 'uuid'
                except:
                    pass
            elif x['type'] == 'trojan':
                try:
                    if 'udp' in x:
                        if x['udp'] not in [False, True]:
                            pass
                    if 'skip-cert-verify' in x:
                        if x['skip-cert-verify'] not in [False, True]:
                            pass
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'TJN'
                    authentication = 'password'
                except:
                    pass
            elif x['type'] == 'snell':
                try:
                    if 'udp' in x:
                        if x['udp'] not in [False, True]:
                            pass
                    if 'skip-cert-verify' in x:
                        if x['skip-cert-verify'] not in [False, True]:
                            pass
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SNL'
                    authentication = 'psk'
                except:
                    pass
            elif x['type'] == 'http':
                try:
                    if 'tls' in x:
                        if x['tls'] not in [False, True]:
                            pass
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'HTT'
                    # authentication = 'userpass'
                except:
                    pass
            elif x['type'] == 'socks5':
                try:
                    if 'tls' in x:
                        if x['tls'] not in [False, True]:
                            pass
                    if 'udp' in x:
                        if x['udp'] not in [False, True]:
                            pass
                    if 'skip-cert-verify' in x:
                        if x['skip-cert-verify'] not in [False, True]:
                            pass
                    x['name'] = str(flag.flag(country)) + ' ' + str(country) + ' ' + str(count) + ' ' + 'SK5'
                    # authentication = 'userpass'
                except:
                    pass
            else:
                pass

            #if ip in iplist and x['port'] in iplist[ip]:
            #    if country != 'CN':
            #        pass
            #    else:
            #        if x[authentication] in passlist:
            #            pass
            #        else:
            #            passlist.append(x[authentication])
            #else:
            #    try:
            #        iplist[ip].append(x['port'])
            #    except:
            #        iplist[ip] = []
            #        iplist[ip].append(x['port'])

            clash['proxies'].append(x)
            clash['proxy-groups'][0]['proxies'].append(x['name'])
            clash['proxy-groups'][1]['proxies'].append(x['name'])
            count = count + 1
    try:
        start_push_parse(info)
    except:
        pass
    bar.update(1)


def push(list):
    
    
    passlist = []
    iplist = {}
    passlist = []

    clash = {'proxies': [], 'proxy-groups': [
            {'name': 'automatic', 'type': 'url-test', 'proxies': [], 'url': 'https://www.google.com/favicon.ico',
             'interval': 300}, {'name': '🌐 Proxy', 'type': 'select', 'proxies': ['automatic']}],
             'rules': ['MATCH,🌐 Proxy']}
    with maxminddb.open_database('Country.mmdb') as countrify:
        bar = tqdm(total=len(list), desc='Parse：')
        thread_list = []
        for info in list:
            # 为每个创建线程
            t = threading.Thread(target=push_parse, args=(bar,clash,countrify,info,iplist,passlist))
            # 加入线程池并启动
            thread_list.append(t)
            t.setDaemon(True)
            t.start()
        for t in thread_list:
            t.join()
        bar.close()
            

    with open('output.yaml', 'w') as writer:
        yaml.dump(clash, writer, sort_keys=False)
