
import os

SCRIPT_NAME = os.path.basename(__file__)
AVALIABLE_EXECUTION_COMMANDS = ['c2-analysis', 'dns-analysis', 'ssh-analysis', 'help', 'exit', 'logo']

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

Usage: python analyzer.py [MODE] [OPTIONS]

Available modes:
  c2-analysis <conn.log> <http.log>      Run C2 beaconing detection from Zeek logs.
  dns-analysis <dns.log>                 Analyze rare or typo-squatting DNS queries.
  ssh-analysis <auth.log>                Analyze SSH login patterns with geo-location.

Examples:
  python analyzer.py c2-analysis logs/conn.log logs/http.log output.log
  python analyzer.py dns-analysis logs/dns.log output.log
  python analyzer.py ssh-analysis logs/auth.log


  help, h     Show this guide.


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
