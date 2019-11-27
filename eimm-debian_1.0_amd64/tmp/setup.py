#!/usr/bin/env python3
import os
import sys
import subprocess
import requests
import json
import socket
import urllib3

from uuid import getnode as get_mac
from jinja2 import FileSystemLoader, Environment

urllib3.disable_warnings(urllib3.exceptions.SecurityWarning)

api_url = 'https://imm.engr.unr.edu/ipxe/api/host/'
certs = ("/etc/ssl/private/util.cert.pem","/etc/ssl/private/util.key.pem")

def get_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  ip = s.getsockname()[0]
  s.close()

  return ip

def get_lldp():
  output = subprocess.check_output(["lldpctl", "-f", "json"], shell=True)
  return output.decode('UTF-8')

def render_from_template(directory, template_name, **kwargs):
    loader = FileSystemLoader(directory)
    env = Environment(loader=loader)
    template = env.get_template(template_name)
    return template.render(**kwargs)

def main():
  mac = get_mac()
  mac = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
  hostname = subprocess.run(["hostname"], stdout=subprocess.PIPE)

  params = {'mac__iexact': '%s' % mac }
  r = requests.get(api_url, cert = certs, params = params)

  resp_json = r.json()

  objects = resp_json.get('objects', None)

  machine = None

  if objects is not None and len(objects) > 0:
    machine = objects[0]
  else:
    sys.exit(0)

  update_string = { "ip" : get_ip(),
                    "state" : "RUNNING",
                    "os_family" : "Linux",
                    "online" : True,
                    "lldp" : get_lldp()
                   }
  headers = { 'content-type' : 'application/json' }
  update_url =  'https://imm.engr.unr.edu%s' % machine['resource_uri']



  print("Making request to {0}, params: {1}".format(update_url, update_string))
  r = requests.put(update_url, cert=certs, data=json.dumps(update_string), headers=headers)

  print("Response: %s,%s" % (r.status_code,r.text))

  if len(resp_json['objects']) == 0:
    print("No Machine Found with MAC: %s, exiting..." % mac)
    sys.exit()

  host = resp_json['objects'][0]

  try: #set hostname
    subprocess.run(["hostname", "%s" % host['hostname']], stdout=subprocess.PIPE)
    subprocess.run(["cp", "/etc/hosts_1","/tmp/hosts" ], stdout=subprocess.PIPE)
    subprocess.run(["cp", "/etc/hostname_1","/tmp/hostname" ], stdout=subprocess.PIPE)
    subprocess.run(["sed", "-ie", "s/localhost/%s/g" % host['hostname'], "/tmp/hosts"], stdout=subprocess.PIPE)
    subprocess.run(["sed", "-ie", "s/nfs-netboot/%s/g" % host['hostname'], "/tmp/hostname"], stdout=subprocess.PIPE)
    #subprocess.run(["systemctl", "restart", "syslog" ], stdout=subprocess.PIPE)
  except Exception as e:
    print(e)

if __name__ == '__main__':
  main()


