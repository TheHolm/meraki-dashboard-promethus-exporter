import http.server
import threading
import time
import configargparse
import meraki

def get_devices(devices, dashboard, organization_id):
    devices.extend(dashboard.organizations.getOrganizationDevicesStatuses(organizationId=organization_id, total_pages="all"))
    print('Got', len(devices), 'Devices')

def get_device_statuses(device_statuses, dashboard, organization_id):
    device_statuses.extend(dashboard.organizations.getOrganizationDevicesUplinksLossAndLatency(organizationId=organization_id, ip='8.8.8.8', timespan="120", total_pages="all"))
    print('Got', len(device_statuses), 'Device Statuses')

def get_uplink_statuses(uplink_statuses, dashboard, organization_id):
    uplink_statuses.extend(dashboard.appliance.getOrganizationApplianceUplinkStatuses(organizationId=organization_id, total_pages="all"))
    print('Got', len(uplink_statuses), 'Uplink Statuses')

def get_organization(org_data, dashboard, organization_id):
    org_data.update(dashboard.organizations.getOrganization(organizationId=organization_id))

def get_organizations(orgs_list, dashboard):
    response = dashboard.organizations.getOrganizations()
    for org in response:
        try:
            dashboard.organizations.getOrganizationApiRequestsOverview(organizationId=org['id'])
            orgs_list.append(org['id'])
        except meraki.exceptions.APIError:
            pass

def get_vpn_statuses(vpn_statuses, dashboard, organization_id):
    vpn_statuses.extend(dashboard.appliance.getOrganizationApplianceVpnStatuses(organizationId=organization_id, total_pages='all'))
    print('Got', len(vpn_statuses), 'VPN Statuses')

def get_usage(dashboard, organization_id):
    devices = []
    t1 = threading.Thread(target=get_devices, args=(devices, dashboard, organization_id))
    t1.start()

    device_statuses = []
    t2 = threading.Thread(target=get_device_statuses, args=(device_statuses, dashboard, organization_id))
    t2.start()

    uplink_statuses = []
    t3 = threading.Thread(target=get_uplink_statuses, args=(uplink_statuses, dashboard, organization_id))
    t3.start()

    org_data = {}
    t4 = threading.Thread(target=get_organization, args=(org_data, dashboard, organization_id))
    t4.start()

    vpn_statuses = []
    t5 = threading.Thread(target=get_vpn_statuses, args=(vpn_statuses, dashboard, organization_id))
    t5.start()

    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()

    print('Combining collected data\n')

    the_list = {}
    values_list = ['name', 'model', 'mac', 'wan1Ip', 'wan2Ip', 'lanIp', 'publicIp', 'networkId', 'status', 'usingCellularFailover']
    for device in devices:
        the_list[device['serial']] = {'orgName': org_data['name']}
        for value in values_list:
            the_list[device['serial']][value] = device.get(value)

    for device in device_statuses:
        if device['serial'] not in the_list:
            the_list[device['serial']] = {"missing data": True}
        the_list[device['serial']]['latencyMs'] = device['timeSeries'][-1]['latencyMs']
        the_list[device['serial']]['lossPercent'] = device['timeSeries'][-1]['lossPercent']

    for device in uplink_statuses:
        if device['serial'] not in the_list:
            the_list[device['serial']] = {"missing data": True}
        the_list[device['serial']]['uplinks'] = {uplink['interface']: uplink['status'] for uplink in device['uplinks']}

    for vpn in vpn_statuses:
        if vpn['deviceSerial'] not in the_list:
            the_list[vpn['deviceSerial']] = {"missing data": True}
        the_list[vpn['deviceSerial']]['vpn'] = {
            "networkName": vpn['networkName'],
            "merakiVpnPeers": [
                {
                    "networkName": peer['networkName'],
                    "reachability": peer['reachability']
                } for peer in vpn.get('merakiVpnPeers', [])
            ],
            "thirdPartyVpnPeers": [
                {
                    "name": peer['name'],
                    "publicIp": peer['publicIp'],
                    "reachability": peer['reachability']
                } for peer in vpn.get('thirdPartyVpnPeers', [])
            ]
        }

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
            return

        self._set_headers()
        dashboard = meraki.DashboardAPI(API_KEY, output_log=False, print_console=True)

        if "/organizations" in self.path:
            org_list = []
            get_organizations(org_list, dashboard)
            response = "- targets:\n   - " + "\n   - ".join(org_list)
            self.wfile.write(response.encode('utf-8'))
            self.wfile.write("\n".encode('utf-8'))
            return

        dest_org_id = self.path.split('=')[1]
        print('Target:', dest_org_id)
        organization_id = str(dest_org_id)

        start_time = time.monotonic()

        host_stats = get_usage(dashboard, organization_id)
        print("Reporting on:", len(host_stats), "hosts")

        uplink_statuses = {'active': 0, 'ready': 1, 'connecting': 2, 'not connected': 3, 'failed': 4}

        response = ("# TYPE meraki_device_latency gauge\n"
                    "# TYPE meraki_device_loss_percent gauge\n"
                    "# TYPE meraki_device_status gauge\n"
                    "# TYPE meraki_device_uplink_status gauge\n"
                    "# TYPE meraki_device_using_cellular_failover gauge\n")

        for host, stats in host_stats.items():
            try:
                target = (f'{serial="{host}",name="{stats["name"] if stats["name"] != "" else stats["mac"]}",'
                          f'networkId="{stats["networkId"]}",orgName="{stats["orgName"]}",orgId="{organization_id}"')
            except KeyError:
                break

            if 'latencyMs' in stats:
                response += f'meraki_device_latency{target}} {stats["latencyMs"] / 1000}\n'
            if 'lossPercent' in stats:
                response += f'meraki_device_loss_percent{target}} {stats["lossPercent"]}\n'
            response += f'meraki_device_status{target}} {"1" if stats["status"] == "online" else "0"}\n'
            response += f'meraki_device_using_cellular_failover{target}} {"1" if stats["usingCellularFailover"] else "0"}\n'

            if 'uplinks' in stats:
                for uplink, status in stats['uplinks'].items():
                    response += f'meraki_device_uplink_status{target},uplink="{uplink}"} {uplink_statuses[status]}\n'

            if 'vpn' in stats:
                for peer in stats['vpn']['merakiVpnPeers']:
                    response += (f'meraki_vpn_peer_reachability{target},peerType="meraki",peerName="{peer["networkName"]}"} '
                                f'{"1" if peer["reachability"] == "reachable" else "0"}\n')
                for peer in stats['vpn']['thirdPartyVpnPeers']:
                    response += (f'meraki_vpn_peer_reachability{target},peerType="thirdParty",peerName="{peer["name"]}",peerIp="{peer["publicIp"]}"} '
                                f'{"1" if peer["reachability"] == "reachable" else "0"}\n')

        response += f'# TYPE request_processing_seconds summary\nrequest_processing_seconds {time.monotonic() - start_time}\n'
        self.wfile.write(response.encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        self._set_headers_404()

if __name__ == '__main__':
    parser = configargparse.ArgumentParser(description='Per-User traffic stats Prometheus exporter for Meraki API.')
    parser.add_argument('-k', metavar='API_KEY', type=str, required=True, env_var='MERAKI_API_KEY', help='API Key')
    parser.add_argument('-p', metavar='http_port', type=int, default=9822, help='HTTP port to listen for Prometheus scraper, default 9822')
    parser.add_argument('-i', metavar='bind_to_ip', type=str, default="", help='IP address where HTTP server will listen, default all interfaces')
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
