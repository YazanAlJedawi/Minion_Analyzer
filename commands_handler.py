
import os


LOGO_STR = r"""

 ███╗   ███╗██╗███╗   ██╗██╗ ██████╗ ███╗   ██╗
 ████╗ ████║██║████╗  ██║██║██╔═══██╗████╗  ██║
 ██╔████╔██║██║██╔██╗ ██║██║██║   ██║██╔██╗ ██║
 ██║╚██╔╝██║██║██║╚██╗██║██║██║   ██║██║╚██╗██║
 ██║ ╚═╝ ██║██║██║ ╚████║██║╚██████╔╝██║ ╚████║
 ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝  

        Minion Analyzer Activated
"""

def print_logo():
    print(LOGO_STR)

def help_msg_func():
    return f"""\n
{LOGO_STR}

Usage: python Minion.py [MODE] [OPTIONS]

Available modes:
  c2-analysis <conn.log> <http.log>      Run C2 beaconing detection from Zeek logs.
  dns-analysis <dns.log>                 Analyze rare or typo-squatting DNS queries.
  ssh-analysis <auth.log>                Analyze SSH login patterns with geo-location.

Examples:
  python Minion.py c2-analysis logs/conn.log logs/http.log output.log
  python Minion.py dns-analysis logs/dns.log output.log
  python Minion.py ssh-analysis logs/auth.log


  help      : Show this guide.
  logo      : prints the logo.


Note:
  Logs must follow Zeek TSV format with #fields header line.
  DNS analysis compares domain names against a similarity baseline (default: 'example').
"""

def interface():
    return f"""\n
{LOGO_STR}
This tool allows:
- Detecting beaconing activity
- Performing DNS typo analysis
- Logging SSH activity with geolocation

- "help" to ask for help

Made By:
  - YazanAlJedawi: https://github.com/YazanAlJedawi
"""
