#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

from BaseHTTPServer import BaseHTTPRequestHandler
import urlparse
import json
import shodan

# This code is *highly* inspired from MasterSlash
# The original code is available here: https://github.com/bitbackofen/slash-server-for-mattermost/blob/master/matterslash.py

# Define server address and port, use localhost if you are running this on your Mattermost server.
HOSTNAME = '0.0.0.0'
PORT = 8088
SHODAN_API_KEY = "XXXXXXXXXXXXXXXXXXXXXXXX"
MATTERMOST_TOKEN = "YYYYYYYYYYYYYYYYYYYYYYYY"


# guarantee unicode string
_u = lambda t: t.decode('UTF-8', 'replace') if isinstance(t, str) else t


class MattermostRequest(object):
    """
    This is what we get from Mattermost
    """
    def __init__(self, response_url=None, text=None, token=None, channel_id=None, team_id=None, command=None,
                 team_domain=None, user_name=None, channel_name=None):
        self.response_url = response_url
        self.text = text
        self.token = token
        self.channel_id = channel_id
        self.team_id = team_id
        self.command = command
        self.team_domain = team_domain
        self.user_name = user_name
        self.channel_name = channel_name


class PostHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Respond to a POST request."""
        # Extract the contents of the POST
        length = int(self.headers['Content-Length'])
        post_data = urlparse.parse_qs(self.rfile.read(length).decode('utf-8'))

        # Get POST data and initialize MattermostRequest object
        for key, value in post_data.iteritems():
            if key == 'response_url':
                MattermostRequest.response_url = value
            elif key == 'text':
                MattermostRequest.text = value
            elif key == 'token':
                MattermostRequest.token = value
            elif key == 'channel_id':
                MattermostRequest.channel_id = value
            elif key == 'team_id':
                MattermostRequest.team_id = value
            elif key == 'command':
                MattermostRequest.command = value
            elif key == 'team_domain':
                MattermostRequest.team_domain = value
            elif key == 'user_name':
                MattermostRequest.user_name = value
            elif key == 'channel_name':
                MattermostRequest.channel_name = value

        responsetext = ''

        # Triggering the token is possibly more failure-resistant and secure:
        if MattermostRequest.token[0] == MATTERMOST_TOKEN:
            if MattermostRequest.command[0] == u'/shodan_search_host':
                responsetext = shodan_search_host(MattermostRequest.text)
        else:
            responsetext = 'Nope.'

        if responsetext:
            data = {}
            # 'response_type' may also be 'in_channel'
            data['response_type'] = 'ephemeral'
            data['text'] = responsetext
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data))
        return

def sanitize_data(data):
    if data[0] == '\n':
        data = data[1:]
    if data[-1] == '\n':
        data = data[:-1]
    return data 


def shodan_search_host(ip):
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(ip)
        hostname = 'N/A'
        if len(host['hostnames']) > 0:
            hostname = host['hostnames'][0]
        res =  "##### Basic information\n\n"
        res += "| {} | ({}) |\n|:-|:-|\n".format(host['ip_str'], hostname)
        res += "| City | {} |\n".format(host.get('city', 'n/a'))
        res += "| Country | {} |\n".format(host.get('country_name', 'n/a'))
        res += "| Organization | {} |\n".format(host.get('org', 'n/a'))
        res += "| ISP | {} |\n".format(host.get('isp', 'n/a'))
        res += "| Last Update | {} |\n".format(host.get('last_update', 'n/a'))
        res += "| ASN | {} |\n".format(host.get('asn', 'n/a'))

        res += "\n\n\n##### Additional details for open ports\n\n\n"
        for item in host['data']:
            res += "***Port***: {}\n".format(item['port'])
            res += "```\n{}```\n\n".format(sanitize_data(item['data']))

        res += "\n\n\nMore information on Shodan at: [https://www.shodan.io/host/{}](https://www.shodan.io/host/{})".format(host['ip_str'], host['ip_str'])
    except Exception as e:
        print e
        res = "***No data available for the IP {}.***".format(ip)
    return res

if __name__ == '__main__':
    from BaseHTTPServer import HTTPServer
    server = HTTPServer((HOSTNAME, PORT), PostHandler)
    print('Starting matterslash server, use <Ctrl-C> to stop')
    server.serve_forever()