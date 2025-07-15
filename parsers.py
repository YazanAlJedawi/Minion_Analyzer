
import re
from datetime import datetime as dt
from geoip import geolite2


class ZeekLogParser:
    def __init__(self, path):
        self.path = path
        self.field_map = []
        self.separator = "\t"
        self._load_header()

    def _load_header(self):
        with open(self.path, 'r') as f:
            for line in f:
                if line.startswith("#separator"):
                    self.separator = line.strip().split()[1].encode('utf-8').decode('unicode_escape')
                elif line.startswith("#fields"):
                    self.field_map = line.strip().split()[1:]
                    break

    def parse_lines(self):
        with open(self.path, 'r') as f:
            for line in f:
                if line.startswith("#"):
                    continue
                values = line.strip().split(self.separator)
                if len(values) != len(self.field_map):
                    continue
                yield dict(zip(self.field_map, values))


def parse_zeek_conn(file_path):
    parser = ZeekLogParser(file_path)
    for record in parser.parse_lines():
        # Convert timestamp to datetime
        try:
            record["ts"] = dt.fromtimestamp(float(record["ts"]))
        except Exception:
            continue
        yield record


def parse_zeek_dns(file_path):
    parser = ZeekLogParser(file_path)
    for record in parser.parse_lines():
        try:
            record["ts"] = dt.fromtimestamp(float(record["ts"]))
        except Exception:
            continue
        yield record


def parse_zeek_http(file_path):
    parser = ZeekLogParser(file_path)
    for record in parser.parse_lines():
        try:
            record["ts"] = dt.fromtimestamp(float(record["ts"]))
        except Exception:
            continue
        yield record



def parse_Auth(log_entry):
    log_data = re.search(
        r"^(?P<ts>\w{3}\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2})"
        r"\s(?P<host>[\w\-]+)"
        r"\s(sshd\[\d{1,6}\]):"
        r"\s(?P<action>Failed|Accepted) password for(\s(?P<invalid>invalid user))?"
        r"\s(?P<user>[^\s]+)"
        r"\s(from)"
        r"\s(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r".*$", log_entry)
    
    if not log_data:
        return None

    r = log_data.groupdict()
    r['ts'] = dt.strptime(r['ts'], "%b %d %H:%M:%S")
    geo_data = geolite2.lookup(r['ip'])
    r['country'] = geo_data.country if geo_data else None
    return r