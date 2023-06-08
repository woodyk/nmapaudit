#!/usr/bin/env python3
#
# nmapaudit.py - Author: Wadih Khairallah

import io
import os
import sys
import time
import yaml
import asyncio
import ipaddress
import logging as log
import xmltodict as xml
from prettytable import PrettyTable as pt
from prettytable import PLAIN_COLUMNS
from pprint import pprint as pp
from deepdiff import DeepDiff as dd
import argparse

def getconfig(config_file):
    """Get configuration options"""
    try:
        with open(config_file, "r") as file:
            config = yaml.load(file, Loader=yaml.FullLoader)
    except:
        print("Unable to read %s." % config_file)
        sys.exit(1)

    return config

def flatten(objs):
    """Flatten objects into list"""
    list_return = []
    if type(objs) is dict:
        list_return.append(objs)

    elif type(objs) is list:
        for obj in objs:
            list_return.append(obj)

    return list_return 

def getports(requests):
    """Pull all ports for each scanned object"""
    ports = {}
    for task in requests:
        request = requests[task]['nmaprun']

        hosts = []
        if 'host' in request:
            hosts = flatten(request['host'])

        for host in hosts:
            addresses = flatten(host['address'])
            addr = addresses[0]['@addr']
            ports[addr] = flatten(host['ports']['port'])
            for port in ports[addr]:
                port['service'] = 0
                port['state'] = 0

    return ports

def gethist(histfile):
    """Get scan results from prior run"""
    try:
        with open(histfile, "r") as file:
            history = yaml.load(file, Loader=yaml.FullLoader)
    except:
        return False

    return history

def writehist(histfile, results):
    """Write scan results to file for next run"""
    try:
        with open(histfile, "w") as file:
            file.write(yaml.dump(results))
    except:
        print("Unable to write to %s." % histfile)
        return False

    file.close()

    return True

async def scan(host):
    """Scan the given host"""
    global portlist
    #command = "nmap -p 0-65535 --open -Pn -oX - " + host
    #command = "nmap -p 22,80,443,7846 --open -Pn -oX - " + host
    command = "nmap -p " + portlist + " --open -Pn -oX - " + host

    process = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE
        )

    #print("Scanning host %s: %s" % (host, process.pid))
    stdout, stderr = await process.communicate()

    return stdout 

async def run(nets):
    """Execute the task group"""
    # Create and run our tasks
    tasks = []

    # Supported in python 3.11
    #async with asyncio.TaskGroup() as tg:
    #    for net in nets:
    #        tasks.append(tg.create_task(scan(net)))

    for net in nets:
        tasks.append(asyncio.create_task(scan(net)))

    await asyncio.gather(*tasks)

    # Gather results from tasks
    results = {}
    for task in tasks:
        name = task.get_name()
        results[name] = xml.parse(task.result())

    for result in results:
        content = results[result]
        parse = content['nmaprun']['@args'].split()
        content['nmaprun']['target'] = parse.pop()
        parse.clear()

    return results
    pass

async def batch(maxminions, hostnames):
    """Populate our exec group and run the group"""
    returns = {} 
    revmap = {}
    nets = [] 
    netmap = {}

    # Crete groups of maxminions size and execute
    minions = 0
    while hostnames:
        i = hostnames.pop()

        for hostname in i:
            net = i[hostname]
            revmap[net] = hostname

        netmap[net] = i

        if minions <= maxminions:
            nets.append(net)            
            minions += 1

        if minions == maxminions:
            returns.update(await run(nets))
            nets.clear()
            minions = 0

    # Execute remaining scans
    returns.update(await run(nets)) 

    results = {}
    for returned in returns:
        content = returns[returned]
        target = content['nmaprun']['target']
        results[revmap[target]] = content

    returns.clear()

    return results
    pass

def main(args):
    """ Main """
    # Set our working directory the same as the scripts absolute path
    script_path = os.path.realpath(__file__).split("/")
    script_path.pop()
    script_path = "/".join(script_path)
    os.chdir(script_path)

    # Populate our configuration options
    global portlist
    global logfile
    config_file = "nmapaudit.conf.yml"
    config = getconfig(config_file)

    maxminions = config['maxMinions']
    histfile = config['histFile']
    networks = config['networks'].copy()
    pulledports = config['ports']
    portlist = ",".join(pulledports)

    # Prepare logging
    logfile = config['logFile']
    log.basicConfig(filename=logfile,
                    encoding='utf-8',
                    level=log.INFO,
                    format='%(asctime)s: %(message)s',
                    datefmt='%m/%d/%Y %T'
                )

    log.info("Started")

    # Pull previous scan history
    history = gethist(histfile) 

    # Run configured scans
    results = asyncio.run(batch(maxminions, networks))

    # Compare our results
    if history:
        current_ports = getports(results)
        previous_ports = getports(history)

        # Compare configured hosts to scans
        tablegroups = []
        for mapping in config['networks']:
            for label, network in mapping.items():
                ips = list(ipaddress.ip_network(network, strict=False).hosts())
                if len(ips) >= 4:
                    ips.pop(-1)
                    ips.pop(0)

                iptables = []
                for ip in ips:
                    ip = str(ip)

                    if ip not in previous_ports:
                        previous_ports[ip] = []

                    if ip not in current_ports:
                        current_ports[ip] = []

                    diff = dd(previous_ports[ip],
                              current_ports[ip],
                              ignore_order=True,
                              report_repetition=True
                            )

                    p = []
                    for prev in previous_ports[ip]:
                        p.append(int(prev['@portid']))

                    c = []
                    for cur in current_ports[ip]:
                        c.append(int(cur['@portid']))

                    p.sort()
                    c.sort()
                    pad = -1
                    tot = -1

                    if len(p) > len(c):
                        tot = len(p)
                        pad = len(p) - len(c)
                        while pad > 0:
                            c.append("-")
                            pad -= 1
                    elif len(c) > len(p):
                        tot = len(c)
                        pad = len(c) - len(p)
                        while pad > 0:
                            p.append("-")
                            pad -= 1
                    elif len(p) == 0 and len(c) == 0:
                        tot = 1
                        pad = 1
                        while pad > 0:
                            p.append("-")
                            c.append("-")
                            pad -= 1
                    else:
                        tot = len(p)

                    filler = []
                    while tot > 0:
                        filler.append("-")
                        tot -= 1

                    iptab = pt()
                    iptab._min_width = {ip:35, "before":15, "after":15}
                    iptab.add_column(ip, filler, align='c')
                    iptab.add_column("before", p, align='l')
                    iptab.add_column("after", c, align='l')
                    iptables.append(iptab)
                    iptab.set_style(PLAIN_COLUMNS)

                if len(diff) > 0:
                    label = label + " [changed]"

                header = pt()
                header._min_width = {label:80}
                header.add_column(label, iptables)
                tablegroups.append(header)
                #print(header)

        container = pt()
        container._min_width = {"Scan Results":80}
        container.add_column("Scan Results", tablegroups, align='c')
        
        output = container.get_string()
        if args.stdout or (not args.stdout and not args.output_file):
            print(output)
        if args.output_file:
            timestamp = time.strftime("%m-%d-%y-%H%M", time.gmtime())
            file_name = os.path.join(args.output_dir, f"nmapaudit-{timestamp}.txt")
            try:
                with open(file_name, "w") as file:
                    file.write(output)
            except Exception as e:
                print("Error writing to file:", e)

    # Write out our results for next run
    writehist(histfile, results)

    log.info("Finished")

    return

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap Audit Script")
    parser.add_argument("--stdout", action="store_true", help="Display output to stdout")
    parser.add_argument("--output-file", action="store_true", help="Save output to a file with timestamp")
    parser.add_argument("--output-dir", type=str, default="./", help="Directory to write output file to")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    main(args)
    sys.exit(0)
