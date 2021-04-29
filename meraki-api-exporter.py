import http.server
import threading
import argparse
import time

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
    for org in response:  # If you know better way to check that API key has access to an Org, please let me know. (This will rate throtled big time )
        try:
            dashboard.organizations.getOrganizationApiRequestsOverview(organizationId=org['id'])
            orgs_list.append(org['id'])
        except meraki.exceptions.APIError:
            pass


def get_usage(dashboard, organizationId):
    # launching threads to collect data.
    # if more indexes is requred it is good time to conver it to loop.

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

    t1.join()
    t2.join()
    t3.join()
    t4.join()

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
        dashboard = meraki.DashboardAPI(API_KEY, output_log=False, print_console=True)

        if "/organizations" in self.path:   # Generating list ov avialable organizations for API keys.
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
        self.wfile.write("\n".encode('utf-8'))

        host_stats = get_usage(dashboard, organizationId)
        print("Reporting on:", len(host_stats), "hosts")
        '''{ 'latencyMs': 23.7,
             'lossPercent': 0.0,
             'name': 'TestSite',
             'mac': 'e0:cb:00:00:00:00'
             'networkId': 'L_12345678',
             'publicIp': '1.2.3.4',
             'status': 'online',
             'uplinks': {'cellular': 'ready', 'wan1': 'active'},
             'usingCellularFailover': False,
             'wan1Ip': '1.2.3.4'}
        '''
        # uplink statuses
        uplink_statuses = {'active': 0,
                           'ready': 1,
                           'connecting': 2,
                           'not connected': 3,
                           'failed': 4}

        responce = "# TYPE latencyMs gauge\n" + \
                   "# TYPE lossPercent gauge\n" + \
                   "# TYPE status gauge\n" + \
                   "# TYPE uplinkStatus gauge\n" + \
                   "# TYPE usingCellularFailover gauge\n"

        for host in host_stats.keys():
            try:
                target = '{ serial="' + host + \
                         '", name="' + (host_stats[host]['name'] if host_stats[host]['name'] != "" else host_stats[host]['mac'] ) + \
                         '",networkId="' + host_stats[host]['networkId'] + \
                         '",orgName="' + host_stats[host]['orgName'] + \
                         '",orgId="' + organizationId + \
                         '"'
            except KeyError:
                break
            # values={ 'latencyMs': lambda a : str(a)}
            try:
                if host_stats[host]['latencyMs'] is not None:
                    responce = responce + 'latencyMs' + target + '} ' + str(host_stats[host]['latencyMs']) + '\n'
                if host_stats[host]['lossPercent'] is not None:
                    responce = responce + 'lossPercent' + target + '} ' + str(host_stats[host]['lossPercent']) + '\n'
            except KeyError:
                pass
            try:
                responce = responce + 'status' + target + '} ' + ('1' if host_stats[host]['status'] == 'online' else '0') + '\n'
            except KeyError:
                pass
            try:
                responce = responce + 'usingCellularFailover' + target + '} ' + ('1' if host_stats[host]['usingCellularFailover'] else '0') + '\n'
            except KeyError:
                pass
            if 'uplinks' in host_stats[host]:
                for uplink in host_stats[host]['uplinks'].keys():
                    responce = responce + 'uplinkStatus' + target + ',uplink="' + uplink + '"} ' + str(uplink_statuses[host_stats[host]['uplinks'][uplink]]) + '\n'

        responce = responce + '# TYPE request_processing_seconds summary\n'
        responce = responce + 'request_processing_seconds ' + str(time.monotonic() - start_time) + '\n'

        self.wfile.write(responce.encode('utf-8'))
        self.wfile.write("\n".encode('utf-8'))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        # Doesn't do anything with posted data
        self._set_headers_404()
        return()
        self._set_headers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Per-User traffic stats Pronethetius exporter for Cisco LNS.')
    parser.add_argument('-k', metavar='API_KEY', type=str, required=True,
                        help='API Key')
    parser.add_argument('-p', metavar='http_port', type=int, default=9822,
                        help='HTTP port to listen for Promethius scrapper, default 8000')
    parser.add_argument('-i', metavar='bind_to_ip', type=str, default="",
                        help='IP address where HTTP server will listen, default all interfaces')
    args = vars(parser.parse_args())
    HTTP_PORT_NUMBER = args['p']
    HTTP_BIND_IP = args['i']
    API_KEY = args['k']

    # starting server
    server_class = MyHandler
    httpd = http.server.ThreadingHTTPServer((HTTP_BIND_IP, HTTP_PORT_NUMBER), server_class)
    print(time.asctime(), "Server Starts - %s:%s" % ("*" if HTTP_BIND_IP == '' else HTTP_BIND_IP, HTTP_PORT_NUMBER))
    httpd.serve_forever()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), "Server Stops - %s:%s" % ("localhost", HTTP_PORT_NUMBER))
