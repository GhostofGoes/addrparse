# http://multivax.com/last_question.html

"""Convert mixed input values to normalized IP addresses.

The goal of addrparse is to bring the power of libraries like
`python-dateutil`` and ``arrow`` to network addressing. It is designed
to work out of the box for common use cases, such as user-specified
values and command output, while also providing a robust set of easily
accessible features for more complex use cases.

Note that input is assumed to be TRUSTED. If untrusted input must be
used, proceed with extreme caution. Do NOT enable file input parsing.
Avoid the flags for forward or reverse domain name resolution, as
these have a high potential for denial of service attacks or
information leakage. They can even be used to make YOU the source
of a denial of service attack! tl;dr: be careful, think about the
ramifications of the flags you enable, and sanitize any input.

Inputs:
* IPv4/IPv6 host addresses in standard notation
* IPv4/IPv6 subnets using CIDR "slash" notation,
e.g. "192.168.0.0/24" or "2001:db8::/32"
* Tuples with a pair of IP address and subnet mask in standard notation.
Example: ('192.168.0.0', '255.255.255.0')
* "nmap-style" range of IPv4 addresses (e.g. "192.168.0.20-40", "172.16-17.0.0")
* "verbose" ranges of IPv4 addresses (e.g. "192.168.0.20-192.168.0.40")
* Domain names (e.g. "localhost", "google.com")
* "file://" URLs a local file containing values to parse.
  File formats: plaintext (one value per line), CSV, JSON
  By default, files will be read as UTF-8. This can be changed by setting
  the ENCODING global parameter.
  Newline characters will be normalized (LF, CR, CRLF)

Outputs:
* Strings in dotted-decimal (IPv4) or colon-separated (IPv6) forms.
* IPAddress and/or IPNetwork objects (from the ``ipaddress`` module in the
Python standard library).
"""

import csv
import json
import logging
import os.path
from ipaddress import (
    AddressValueError, IPv4Address, IPv4Network,
    IPv6Address, IPv6Network, ip_address, ip_network
)
from pathlib import Path
from typing import List, Union, Optional, Iterable

_log = logging.getLogger('addrparse')
_log.addHandler(logging.NullHandler)
_log.setLevel(logging.WARNING)


Net = Union[IPv4Network, IPv6Network]
IP = Union[IPv4Address, IPv6Address]
Parsable = Union[str, bytes, tuple, Iterable, IP, Net]
ParsableValues = Union[Parsable, Iterable[Parsable]]

# TODO (Project)
#   Sphinx docs
#   ReadTheDocs
#   TravisCI
#   Appveyor
#   Unit tests
#   Coveralls


# TODO (Features)
#   Integer values


def parse(
    to_parse: ParsableValues,
    remove_duplicates: bool = True,
    read_files: bool = False,
    domains_to_addrs: bool = False,
    only_addresses: bool = False,
    addrs_to_domains: bool = False,
    only_hostnames: bool = False
) -> List[str]:
    """Parses mixed input(s) to a list of IP address and/or domain name strings.

    Note that a list will ALWAYS be returned, even if the input is a
    single value, and when possible you should assume and handle the
    return of a list with more than one value. There are a number of
    edge cases where a single value can have multiple results,
    such as subnets, IP ranges, or files.

    Args:
        to_parse: Value to parse. This can be a string, tuple, IPAddress,
        IPNetwork, or a iterable containing any of these values, such as
        a list or set. Tuples are treated as subnets and interpreted as
        IP address string and subnet mask. Iterables can be nested.
        remove_duplicates: If duplicate results should be removed
        read_files: search for files in the values and read their contents.
        domains_to_addrs: If true, any non-address strings will treated as
        potential domain names and resolved into IPs. If the resolution
        fails, they are either discarded or preserved-as is, depending on
        the value of allow_unknowns.
        only_addresses: only return valid IP address strings. Any other
        strings, including domain names, will be filtered and discarded.
        addrs_to_domains: Attempt to resolve IPs into domain names and
        return any that successfully resolve.
        only_hostnames: only return valid domain or host name strings.
        any other strings, including addresses, will be discarded. This
        is generally recommended to be used with reverse_resolve.
    """
    if isinstance(to_parse, bytes):
        to_parse = to_parse.decode('utf-8')

    if isinstance(to_parse, list):
        return normalize(to_parse)


def parse_to_objs(
    to_parse: ParsableValues,
    remove_duplicates: bool = True,
    read_files: bool = False,
    domains_to_addrs: bool = False,
    only_addresses: bool = False
) -> List[Union[IP, Net]]:
    """Parses mixed input to a list of ipaddress objects.

    Args:
        to_parse: Value to parse. This can be a string or iterable of strings,
        such as a list or set.
        remove_duplicates: If duplicate results should be removed
        read_files: search for files in the values and read their contents.
        domains_to_addrs: If true, any non-address strings will treated as
        potential domain names and resolved into IPs. If the resolution
        fails, they are either discarded or preserved-as is, depending on
        the value of allow_unknowns.
        only_addresses: only return IPAddress objects. IPNetwork objects
        will be converted into their constituent addresses, and duplicates
        removed if remove_duplicates is True.
    """


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


# TODO: file://, if there's only one slash parse as if root
# TODO: windows paths
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
