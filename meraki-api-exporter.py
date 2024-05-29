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


def get_organizarion(org_data, dashboard, organizationId):
    org_data.update(dashboard.organizations.getOrganization(organizationId=organizationId))


def get_organizarions(orgs_list, dashboard):
    response = dashboard.organizations.getOrganizations()
    for org in response:
        try:
            dashboard.organizations.getOrganizationApiRequestsOverview(organizationId=org['id'])
            orgs_list.append(org['id'])
        except meraki.exceptions.APIError:
            pass


def get_networks(networks, dashboard, organizationId):
    networks.extend(dashboard.organizations.getOrganizationNetworks(organizationId=organizationId, total_pages="all"))
    print('Got', len(networks), 'Networks')


def get_network_clients(clients, dashboard, networkId):
    clients.extend(dashboard.networks.getNetworkClients(networkId=networkId, total_pages="all"))
    print('Got', len(clients), 'Clients')


def get_network_health(health, dashboard, networkId):
    health.append(dashboard.networks.getNetworkHealth(networkId=networkId))
    print('Got Network Health')


def get_vpn_statuses(vpnstatuses, dashboard, organizationId):
    vpnstatuses.extend(dashboard.appliance.getOrganizationApplianceVpnStatuses(organizationId=organizationId, total_pages="all"))
    print('Got', len(vpnstatuses), 'VPN Statuses')


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

    org_data = {}
    t4 = threading.Thread(target=get_organizarion, args=(org_data, dashboard, organizationId))
    t4.start()

    networks = []
    t5 = threading.Thread(target=get_networks, args=(networks, dashboard, organizationId))
    t5.start()

    vpnstatuses = []
    t6 = threading.Thread(target=get_vpn_statuses, args=(vpnstatuses, dashboard, organizationId))
    t6.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()
    t6.join()

    clients = []
    health = []

    for network in networks:
        t7 = threading.Thread(target=get_network_clients, args=(clients, dashboard, network['id']))
        t7.start()
        t8 = threading.Thread(target=get_network_health, args=(health, dashboard, network['id']))
        t8.start()
        t7.join()
        t8.join()

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
            the_list[device['serial']]
        except KeyError:
            the_list[device['serial']] = {"missing data": True}

        the_list[device['serial']]['latencyMs'] = device['timeSeries'][-1]['latencyMs']
        the_list[device['serial']]['lossPercent'] = device['timeSeries'][-1]['lossPercent']

    for device in uplinkstatuses:
        try:
            the_list[device['serial']]
        except KeyError:
            the_list[device['serial']] = {"missing data": True}
        the_list[device['serial']]['uplinks'] = {}
        for uplink in device['uplinks']:
            the_list[device['serial']]['uplinks'][uplink['interface']] = uplink['status']

    the_list['networks'] = networks
    the_list['clients'] = clients
    the_list['health'] = health
    the_list['vpnstatuses'] = vpnstatuses

    print('Done')
    return the_list


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
        dashboard = meraki.DashboardAPI(API_KEY, output_log=False, print_console=True)

        if "/organizations" in self.path:
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

        responce = "# TYPE meraki_device_latency gauge\n" + \
                   "# TYPE meraki_device_loss_percent gauge\n" + \
                   "# TYPE meraki_device_status gauge\n" + \
                   "# TYPE meraki_device_uplink_status gauge\n" + \
                   "# TYPE meraki_device_using_cellular_failover gauge\n" + \
                   "# TYPE meraki_appliance_vpn_status gauge\n"

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

        for vpn in host_stats['vpnstatuses']:
            try:
                vpn_target = '{networkId="' + vpn['networkId'] + '",networkName="' + vpn['networkName'] + '",deviceSerial="' + vpn['deviceSerial'] + '"'
                responce += 'meraki_appliance_vpn_status' + vpn_target + ',vpnMode="' + vpn['vpnMode'] + '",deviceStatus="' + vpn['deviceStatus'] + '"} 1\n'
                for uplink in vpn['uplinks']:
                    uplink_target = vpn_target + ',uplink="' + uplink['interface'] + '",publicIp="' + uplink['publicIp'] + '"'
                    responce += 'meraki_appliance_vpn_status' + uplink_target + ',uplinkStatus="online"} 1\n'
                for subnet in vpn['exportedSubnets']:
                    subnet_target = vpn_target + ',subnet="' + subnet['subnet'] + '",subnetName="' + subnet['name'] + '"'
                    responce += 'meraki_appliance_vpn_status' + subnet_target + ',subnetStatus="exported"} 1\n'
                for peer in vpn['merakiVpnPeers']:
                    peer_target = vpn_target + ',peerNetworkId="' + peer['networkId'] + '",peerNetworkName="' + peer['networkName'] + '",reachability="' + peer['reachability'] + '"'
                    responce += 'meraki_appliance_vpn_status' + peer_target + ',peerType="meraki"} 1\n'
                for peer in vpn['thirdPartyVpnPeers']:
                    peer_target = vpn_target + ',peerName="' + peer['name'] + '",peerPublicIp="' + peer['publicIp'] + '",reachability="' + peer['reachability'] + '"'
                    responce += 'meraki_appliance_vpn_status' + peer_target + ',peerType="thirdParty"} 1\n'
            except KeyError:
                pass

        responce += '# TYPE request_processing_seconds summary\n'
        responce += 'request_processing_seconds ' + str(time.monotonic() - start_time) + '\n'

        self.wfile.write(responce.encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        self._set_headers_404()
        return()
        self._set_headers()


if __name__ == '__main__':
    parser = configargparse.ArgumentParser(description='Per-User traffic stats Prometheus exporter for Meraki API.')
    parser.add_argument('-k', metavar='API_KEY', type=str, required=True,
                        env_var='MERAKI_API_KEY', help='API Key')
    parser.add_argument('-p', metavar='http_port', type=int, default=9822,
                        help='HTTP port to listen for Prometheus scraper, default 9822')
    parser.add_argument('-i', metavar='bind_to_ip', type=str, default="",
                        help='IP address where HTTP server will listen, default all interfaces')
    args = vars(parser.parse_args())
    HTTP_PORT_NUMBER = args['p']
    HTTP_BIND_IP = args['i']
    API_KEY = args['k']

    server_class = MyHandler
    httpd = http.server.ThreadingHTTPServer((HTTP_BIND_IP, HTTP_PORT_NUMBER), server_class)
    print(time.asctime(), "Server Starts - %s:%s" % ("*" if HTTP_BIND_IP == '' else HTTP_BIND_IP, HTTP_PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % ("localhost", HTTP_PORT_NUMBER))
