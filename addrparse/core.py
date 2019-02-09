"""Convert mixed input values to normalized IP addresses.

Inputs:
* IPv4/IPv6 host address in standard notation
* IPv4/IPv6 subnet using CIDR "slash" notation,
e.g. "192.168.0.0/24" or "2001:db8::/32"
* "nmap-style" range of IPv4 addresses (e.g. "192.168.0.20-40", "172.16-17.0.0")
* "verbose" ranges of IPv4 addresses (e.g. "192.168.0.20-192.168.0.40")
* Domain names (e.g. "localhost", "google.com")
* Filesystem path to a file containing values to parse.
  File formats: plaintext (one value per line), CSV, JSON
  By default, files will be read as UTF-8. This can be changed by setting
  the ENCODING global parameter.
  Newline characters will be normalized (LF, CR, CRLF)

Outputs:
* Strings in dotted-decimal or colon-separated form.
* IPAddress and/or IPNetwork objects
"""

import logging
import os.path
import csv
import json
from pathlib import Path
from typing import List, Union, Optional
from ipaddress import (
    AddressValueError, IPv4Address, IPv4Network,
    IPv6Address, IPv6Network, ip_address, ip_network
)

_log = logging.getLogger('addrparse')
_log.addHandler(logging.NullHandler)
_log.setLevel(logging.WARNING)


Net = Union[IPv4Network, IPv6Network]
IP = Union[IPv4Address, IPv6Address]
Obj = Union[Net, IP]


def normalize(
        values: List[str],
        remove_duplicates: bool = True,
        read_files: bool = False,
        allow_unknowns: bool = False
    ) -> List[str]:
    """Normalizes mixed inputs to strings.

    Args:
        values: Values to normalize
        remove_duplicates: If duplicate results should be removed
        read_files: search for files in the values and read their contents
        allow_unknowns: permit and pass through non-address values, such as hostnames
    """
    addrs = normalize_to_objects(
        values, remove_duplicates, read_files, preserve_networks=False)
    addrs = [str(a) for a in addrs]  # Convert objects to strings
    return addrs


def normalize_to_objects(
        values: List[str],
        remove_duplicates: bool = True,
        read_files: bool = False,
        preserve_networks: bool = True,
        allow_unknowns: bool = False
    ) -> List[Net]:
    """Normalizes mixed inputs to IPAddress objects."""
    addrs = []

    for value in values:
        # Parse values from a file
        if read_files and os.path.exists(value):
            file_values = read_file(value)
            if file_values:
                addrs.extend(file_values)

    # Convert any network objects into their constitute hosts
    if not preserve_networks:
        addrs = [x.hosts() for x in addrs if
                 isinstance(x, (IPv4Network, IPv6Network))]

    # Remove any duplicate addresses
    if remove_duplicates:
        addrs = list(set(addrs))
    return addrs


def parse_value(value: str):
    if '/' in value:
        try:
            obj = ip_network(value)
        except (ValueError, AddressValueError):
            pass

    try:
        obj = ip_address(value)
    except (ValueError, AddressValueError):
        pass



def normalize_file(
        file: Union[str, Path],
        remove_duplicates: bool = True,
        encoding: str = 'utf-8'
    ) -> Optional[List[str]]:
    """Normalize values read from a file."""
    if not os.path.exists(file):
        _log.error(f"Failed to normalize file {str(file)}: file does not exist")
        return None
    path = Path(file).resolve()
    values = read_file(path)
    if not values:
        return None
    addrs = normalize(
        values, remove_duplicates=remove_duplicates, read_files=False)
    return addrs


def read_file(path: Union[str, Path], encoding: str = 'utf-8') -> Optional[List[str]]:
    """Read values from a file."""
    if isinstance(path, str):
        path = Path(path).resolve()
    values: List[str] = []
    if path.suffix == '.csv':
        with path.open(encoding=encoding, newline='') as csvfile:
            values = [row for row in csv.reader(csvfile)]
    elif path.suffix == '.json':
        with path.open(encoding=encoding) as jsonfile:
            values = json.load(jsonfile)
        if not isinstance(values, list):
            _log.error(f"Expected a list in JSON file {path.name},"
                       f"got {type(values).__name__}")
            return None
    else:  # Parse as text, one value per line
        data = path.read_text(encoding=encoding)
        values = [line for line in data.split('\n') if line != '']
    return values
