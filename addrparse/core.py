"""The core functionality for addrparse.

Functions that take mixed input and spit out a normalized set.


What's in mixed input:
* Filenames: text file, JSON file, INI file?
* CIDR-specified ranges
* "nmap"-style ranges (e.g. 192.168.0.20-40, 172.16-17.0.0)
* "verbose" ranges (e.g. 192.168.0.20-192.168.0.40)
* Domain names
* Plain jane IP addresses (IPv4 and IPv6!)

"""

import ipaddress
import os
import sys
from pathlib import Path
from typing import Set, Dict


def to_strings():
    pass


# returns set of IPAddress objects
def to_objs():
    pass




