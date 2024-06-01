import http.server
import threading
import time

import configargparse
import meraki


def get_devices(devices, dashboard, organizationId):
    devices.extend(dashboard.organizations.getOrganizationDevicesStatuses(organizationId=organizationId, total_pages="all"))
    print('Got', len(devices), 'Devices')


def get_device_statuses(devicesdtatuses, dashboard, organizationId):
    devicesdtatuses.extend(dashboard.organizations.getOrganizationDevicesUplinksLossAndLatency(organizationId=organizationId, ip='8.8.8.8', timespan="120", total_pages="all"))
    print('Got ', len(devicesdtatuses), 'Device Statuses')


def get_uplink_statuses(uplinkstatuses, dashboard, organizationId):
    uplinkstatuses.extend(dashboard.appliance.getOrganizationApplianceUplinkStatuses(organizationId=organizationId, total_pages="all"))
    print('Got ', len(uplinkstatuses), 'Uplink Statuses')


def get_vpn_statuses(vpnstatuses, dashboard, organizationId):
    vpnstatuses.extend(dashboard.appliance.getOrganizationApplianceVpnStatuses(organizationId=organizationId, total_pages="all"))
    print('Got ', len(vpnstatuses), 'VPN Statuses')


def get_organizarion(org_data, dashboard, organizationId):
    org_data.update(dashboard.organizations.getOrganization(organizationId=organizationId))


def get_organizarions(orgs_list, dashboard):
    response = dashboard.organizations.getOrganizations()
    for org in response:  # If you know better way to check that API key has access to an Org, please let me know. (This will rate throtled big time )
        try:
            dashboard.organizations.getOrganizationSummaryTopDevicesByUsage(organizationId=org['id'])
            orgs_list.append(org['id'])
        except meraki.exceptions.APIError:
            pass


def get_usage(dashboard, organizationId):
    devices = []
    t1 = threading.Thread(target=get_devices, args=(devices, dashboard, organizationId))
    t1.start()

    devicesdtatuses = []
    t2 = threading.Thread(target=get_device_statuses, args=(devicesdtatuses, dashboard, organizationId))
    t2.start()

    uplinkstatuses = []
    t3 = threading.Thread(target=get_uplink_statuses, args=(uplinkstatuses, dashboard, organizationId))
    t3.start()

    if 'vpn' in COLLECT_EXTRA:
        vpnstatuses = []
        t4 = threading.Thread(target=get_vpn_statuses, args=(vpnstatuses, dashboard, organizationId))
        t4.start()

    org_data = {}
    t5 = threading.Thread(target=get_organizarion, args=(org_data, dashboard, organizationId))
    t5.start()

    t1.join()
    t2.join()
    t3.join()
    if 'vpn' in COLLECT_EXTRA:
        t4.join()
    t5.join()

    print('Combining collected data\n')

    the_list = {}
    values_list = ['name', 'model', 'mac', 'wan1Ip', 'wan2Ip', 'lanIp', 'publicIp', 'networkId', 'status', 'usingCellularFailover']
    for device in devices:
        the_list[device['serial']] = {}
        the_list[device['serial']]['orgName'] = org_data['name']
        for value in values_list:
            try:
                if device[value] is not None:
                    the_list[device['serial']][value] = device[value]
            except KeyError:
                pass

    for device in devicesdtatuses:
        try:
            the_list[device['serial']]  # should give me KeyError if devices was not picket up by previous search.
        except KeyError:
            the_list[device['serial']] = {"missing data": True}

        the_list[device['serial']]['latencyMs'] = device['timeSeries'][-1]['latencyMs']
        the_list[device['serial']]['lossPercent'] = device['timeSeries'][-1]['lossPercent']

    for device in uplinkstatuses:
        try:
            the_list[device['serial']]  # should give me KeyError if devices was not picket up by previous search.
        except KeyError:
            the_list[device['serial']] = {"missing data": True}
        the_list[device['serial']]['uplinks'] = {}
        for uplink in device['uplinks']:
            the_list[device['serial']]['uplinks'][uplink['interface']] = uplink['status']

    if 'vpn' in COLLECT_EXTRA:
        for vpn in vpnstatuses:
            try:
                the_list[vpn['deviceSerial']]
            except KeyError:
                the_list[vpn['deviceSerial']] = {"missing data": True}

            the_list[vpn['deviceSerial']]['vpnMode'] = vpn['vpnMode']
            the_list[vpn['deviceSerial']]['exportedSubnets'] = [subnet['subnet'] for subnet in vpn['exportedSubnets']]
            the_list[vpn['deviceSerial']]['merakiVpnPeers'] = vpn['merakiVpnPeers']
            the_list[vpn['deviceSerial']]['thirdPartyVpnPeers'] = vpn['thirdPartyVpnPeers']

    print('Done')
    return(the_list)
# end of get_usage()


class MyHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()

    def _set_headers_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.end_headers()

    def do_GET(self):

        if "/?target=" not in self.path and "/organizations" not in self.path:
            self._set_headers_404()
            return()

        self._set_headers()
        dashboard = meraki.DashboardAPI(API_KEY, output_log=False, print_console=True, maximum_retries=20)

        if "/organizations" in self.path:   # Generating list of avialable organizations for API keys.
            org_list = list()
            get_organizarions(org_list, dashboard)
            responce = "- targets:\n   - " + "\n   - ".join(org_list)
            self.wfile.write(responce.encode('utf-8'))
            self.wfile.write("\n".encode('utf-8'))
            return

        dest_orgId = self.path.split('=')[1]
        print('Target: ', dest_orgId)
        organizationId = str(dest_orgId)

        start_time = time.monotonic()

        host_stats = get_usage(dashboard, organizationId)
        print("Reporting on:", len(host_stats), "hosts")

        uplink_statuses = {'active': 0, 'ready': 1, 'connecting': 2, 'not connected': 3, 'failed': 4}

        responce = """
# HELP meraki_device_latency The latency of the Meraki device in milliseconds
# TYPE meraki_device_latency gauge
# UNIT meraki_device_latency milliseconds
# HELP meraki_device_loss_percent The packet loss percentage of the Meraki device
# TYPE meraki_device_loss_percent gauge
# UNIT meraki_device_loss_percent percent
# HELP meraki_device_status The status of the Meraki device (1 for online, 0 for offline)
# TYPE meraki_device_status gauge
# UNIT meraki_device_status boolean
# HELP meraki_device_uplink_status The status of the uplink of the Meraki device
# TYPE meraki_device_uplink_status gauge
# UNIT meraki_device_uplink_status status_code
# HELP meraki_device_using_cellular_failover Whether the Meraki device is using cellular failover (1 for true, 0 for false)
# TYPE meraki_device_using_cellular_failover gauge
# UNIT meraki_device_using_cellular_failover boolean
"""
        if 'vpn' in COLLECT_EXTRA:
            responce +="""
# HELP meraki_vpn_mode The VPN mode of the Meraki device (1 for hub, 0 for spoke)
# TYPE meraki_vpn_mode gauge
# UNIT meraki_vpn_mode boolean
# HELP meraki_vpn_exported_subnets The exported subnets of the Meraki VPN
# TYPE meraki_vpn_exported_subnets gauge
# UNIT meraki_vpn_exported_subnets count
# HELP meraki_vpn_meraki_peers The Meraki VPN peers of the Meraki VPN
# TYPE meraki_vpn_meraki_peers gauge
# UNIT meraki_vpn_meraki_peers count
# HELP meraki_vpn_third_party_peers The third-party VPN peers of the Meraki VPN
# TYPE meraki_vpn_third_party_peers gauge
# UNIT meraki_vpn_third_party_peers count
"""

        for host in host_stats.keys():
            try:
                target = '{serial="' + host + \
                         '",name="' + (host_stats[host]['name'] if host_stats[host]['name'] != "" else host_stats[host]['mac'] ) + \
                         '",networkId="' + host_stats[host]['networkId'] + \
                         '",orgName="' + host_stats[host]['orgName'] + \
                         '",orgId="' + organizationId + \
                         '"'
            except KeyError:
                break
            try:
                if host_stats[host]['latencyMs'] is not None:
                    responce += 'meraki_device_latency' + target + '} ' + str(host_stats[host]['latencyMs']/1000) + '\n'
                if host_stats[host]['lossPercent'] is not None:
                    responce += 'meraki_device_loss_percent' + target + '} ' + str(host_stats[host]['lossPercent']) + '\n'
            except KeyError:
                pass
            try:
                responce += 'meraki_device_status' + target + '} ' + ('1' if host_stats[host]['status'] == 'online' else '0') + '\n'
            except KeyError:
                pass
            try:
                responce += 'meraki_device_using_cellular_failover' + target + '} ' + ('1' if host_stats[host]['usingCellularFailover'] else '0') + '\n'
            except KeyError:
                pass
            if 'uplinks' in host_stats[host]:
                for uplink in host_stats[host]['uplinks'].keys():
                    responce += 'meraki_device_uplink_status' + target + ',uplink="' + uplink + '"} ' + str(uplink_statuses[host_stats[host]['uplinks'][uplink]]) + '\n'
            if 'vpnMode' in host_stats[host]:
                responce += 'meraki_vpn_mode' + target + '} ' + ('1' if host_stats[host]['vpnMode'] == 'hub' else '0') + '\n'
            if 'exportedSubnets' in host_stats[host]:
                for subnet in host_stats[host]['exportedSubnets']:
                    responce += 'meraki_vpn_exported_subnets' + target + ',subnet="' + subnet + '"} 1\n'
            if 'merakiVpnPeers' in host_stats[host]:
                for peer in host_stats[host]['merakiVpnPeers']:
                    reachability_value = '1' if peer['reachability'] == 'reachable' else '0'
                    responce += 'meraki_vpn_meraki_peers' + target + ',peer_networkId="' + peer['networkId'] + '",peer_networkName="' + peer['networkName'] + '",reachability="' + peer['reachability'] + '"} ' + reachability_value + '\n'
            if 'thirdPartyVpnPeers' in host_stats[host]:
                for peer in host_stats[host]['thirdPartyVpnPeers']:
                    reachability_value = '1' if peer['reachability'] == 'reachable' else '0'
                    responce += 'meraki_vpn_third_party_peers' + target + ',peer_name="' + peer['name'] + '",peer_publicIp="' + peer['publicIp'] + '",reachability="' + peer['reachability'] + '"} ' + reachability_value + '\n'

        responce += '# TYPE request_processing_seconds summary\n'
        responce += 'request_processing_seconds ' + str(time.monotonic() - start_time) + '\n'

        self.wfile.write(responce.encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        # Doesn't do anything with posted data
        self._set_headers_404()
        return()
        self._set_headers()


if __name__ == '__main__':
    parser = configargparse.ArgumentParser(description='Per-User traffic stats Pronethetius exporter for Meraki API.')
    parser.add_argument('-k', metavar='API_KEY', type=str, required=True,
                        env_var='MERAKI_API_KEY', help='API Key')
    parser.add_argument('-p', metavar='http_port', type=int, default=9822,
                        help='HTTP port to listen for Prometheus scraper, default 9822')
    parser.add_argument('-i', metavar='bind_to_ip', type=str, default="",
                        help='IP address where HTTP server will listen, default all interfaces')
    parser.add_argument('--vpn', dest='collect_vpn_data', action='store_true',
                        help='If set VPN connection statuses will be also collected')
    args = vars(parser.parse_args())
    HTTP_PORT_NUMBER = args['p']
    HTTP_BIND_IP = args['i']
    API_KEY = args['k']
    COLLECT_EXTRA = ()
    COLLECT_EXTRA += ( ('vpn',) if args['collect_vpn_data'] else () )


    # starting server
    server_class = MyHandler
    httpd = http.server.ThreadingHTTPServer((HTTP_BIND_IP, HTTP_PORT_NUMBER), server_class)
    print(time.asctime(), "Server Starts - %s:%s" % ("*" if HTTP_BIND_IP == '' else HTTP_BIND_IP, HTTP_PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % ("localhost", HTTP_PORT_NUMBER))
