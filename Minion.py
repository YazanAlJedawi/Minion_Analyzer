# file: analyzer.py
from commands_handler import *
from parsers import *
from collections import Counter
from operator import itemgetter
from difflib import SequenceMatcher as sm
from elasticsearch import Elasticsearch
import sys
import json

def getHttpByUid(path):
    r = Counter()
    for log_data in parse_zeek_http(path):
        r.update([log_data['uid']])
    return r


def detectBeacon(conn_path, http_path, export_path=None):
    req = getHttpByUid(http_path)
    beacons = []
    for log_data in parse_zeek_conn(conn_path):
        if log_data.get('service') == "http":
            log_data['requests'] = req[log_data['uid']]
            beacons.append(log_data)

    beacons.sort(key=itemgetter("requests"), reverse=True)

    header = "{:20}\t{:5}\t{:5}".format("Dst. IP", "Duration", "Requests")
    print(header)
    print("-" * len(header))

    export_data = []
    for entry in beacons[:8]:
        print("{:20}\t{:5}\t{:5}".format(entry['dst_ip'], entry['duration'], entry['requests']))
        export_data.append({
            "dst_ip": entry['dst_ip'],
            "duration": entry['duration'],
            "requests": entry['requests']
        })

    if export_path:
        with open(export_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)




def getDnsStats(path, similar_domain="example"):
    domains = Counter()
    for log_data in parse_zeek_dns(path):
        try:
            dns_query = ".".join(log_data['query'].split('.')[-2:])
            domains.update([dns_query])
        except:
            pass

    least_common = domains.most_common()[-10:]
    domain_anomalies = []
    for domain in least_common:
        anomaly = {
            "domain": domain[0],
            "occurence": domain[1],
            "similarity": round(sm(None, domain[0], similar_domain).ratio() * 100)
        }
        domain_anomalies.append(anomaly)

    domain_anomalies.sort(key=itemgetter("similarity"), reverse=True)
    return domain_anomalies




def printDnsAnomalies(path, export_path=None):
    domains = getDnsStats(path)
    print("{:20}\t{}\t{}".format("Domain", "Occurence", "Simmilarity"))
    print("-"*60)

    if export_path:
        with open(export_path, "w") as f:
            json.dump(domains, f, indent=2)

    for domain in domains:
        print("{:20}\t{}\t{}".format(domain['domain'], domain['occurence'], domain['similarity']))



def exportSshActivity(path="log/auth.log"):
    es = Elasticsearch("http://localhost:9200")
    with open(path, "r") as log_file:
        for log_entry in log_file:
            try:
                log_data = parse_Auth(log_entry)
                
                es.index(index="auth", document=log_data)
            except:
                pass
def main():
    try:
        if (sys.argv[1]):
            mode=sys.argv[1]
    except:
        print(interface())
        return
    

    if mode == "help":
        print(help_msg_func())
        return


    elif mode == "c2-analysis":
        if len(sys.argv) < 4:
            print("Usage: python analyzer.py c2-analysis <conn.log> <http.log> <output.log>")
            return
        detectBeacon(sys.argv[2], sys.argv[3], sys.argv[4])

    elif mode == "dns-analysis":
        if len(sys.argv) < 3:
            print("Usage: python analyzer.py dns-analysis <dns.log> <output.log>")
            return
        printDnsAnomalies(sys.argv[2], sys.argv[3])

    elif mode == "ssh-analysis":
        if len(sys.argv) < 3:
            print("Usage: python analyzer.py ssh-analysis <auth.log>")
            return
        exportSshActivity(path=sys.argv[2])

    else:
        print("Invalid mode. Choose from: c2-analysis, dns-analysis, ssh-analysis")

main()
