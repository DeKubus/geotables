import logging
import argparse
import sys
import urllib3
import json
import sys
import re
import subprocess
from datetime import datetime

_IPTABLES_FILENAME = "/tmp/iptables.save"
_DROP_RULE = '-A {} -i {} -m comment --comment "Added by geotables.py" -j DROP'
_RELATED_ESTABLISHED = '-A {} -i {} -m state --state ESTABLISHED,RELATED -m comment --comment "Added by geotables.py" -j ACCEPT'
_ACCEPT_STRING = (
    '-A {} -s {} -i {} -m comment --comment "Added by geotables.py" -j ACCEPT'
)
_FILTER_TABLE_ANCHOR = "*filter\n"


def _filter_table_start(iptables_content):
    """Returns the index of the first rule in the filter table

    Args:
        iptables_content (str): The content of an iptables export

    Returns:
        int: Index of the first rule in the filter able
    """
    filter_anchor_index = iptables_content.find(_FILTER_TABLE_ANCHOR)
    return iptables_content.find("-A ", filter_anchor_index)


def _filter_table_end(iptables_content):
    """Returns the index of the end of the filter table, i.e. the last position before the COMMIT directive

    Args:
        iptables_content (str): The content of an iptables export

    Returns:
        int: Index of the end of the filter able
    """
    start_index = _filter_table_start(iptables_content)
    return iptables_content.find("COMMIT", start_index)


def _filter_table_content(iptables_content):
    """Returns the content of the filter table

    Args:
        iptables_content (str): The content of an iptables export

    Returns:
        str: The contents of the filter table
    """
    start_index = _filter_table_start(iptables_content)
    end_index = _filter_table_end(iptables_content)
    return iptables_content[start_index:end_index]


def _filter_existing(iptables_content, interface, ipvx, chain):
    """Filters all blocks which are already present in the allow table

    Args:
        iptables_content (str): The content of an iptables export
        interface (str): The interface for which the rules will be added
        ipvx ([str]): A list of blocks to (potentially) be added
        chain (str): The name of the chain for which the entries will be compared

    Returns:
        [str]: A filtered list of blocks which are not already present
    """
    to_process = _filter_table_content(iptables_content)
    expression = "^(?=.*?(-A {chn}))(?=.*?(-i {iface}))(?=.*?(-j ACCEPT))()".format(
        chn=chain, iface=interface
    )
    expression += "(?=.*?(-s {}))"
    not_filtered = []
    components = [
        "-A {}".format(chain),
        "-i {}".format(interface),
        "-j ACCEPT",
    ]
    for range in ipvx:
        not_there = True
        for line in to_process.split("\n"):
            if range in line and all(x in line for x in components):
                not_there = False
                break
        if not_there:
            not_filtered.append(range)
    return not_filtered


def _add_default_drop(iptables_content, interface, chain, ipv4=True):
    """Check if iptables backup already contains a default drop rule. Add if if it does not.

    Args:
        iptables_content (string): The contents of the current iptables
        interface (str): The interface for which the rules will be added
        chain (str): The name of the chain for which the drop rule will be added
        ipv4 (bool, optional): If True, the iptables contents passed correspond are from the IPv4 version, else form IPv6. Defaults to True.

    Returns:
        (str): The updated content of iptables
    """
    # there is not docker chain for ipv6
    if chain == "DOCKER-USER" and not ipv4:
        return iptables_content
    related_established_rule = _RELATED_ESTABLISHED.format(chain, interface) + "\n"
    drop_rule = _DROP_RULE.format(chain, interface) + "\n"
    if drop_rule in iptables_content:
        logging.info(
            "Drop rule had already been enabled for the chain {}".format(chain)
        )
        return iptables_content
    else:
        logging.info("Adding drop rule for chain {}".format(chain))
        last_index = _filter_table_end(iptables_content)
        iptables_content = (
            iptables_content[:last_index]
            + related_established_rule
            + drop_rule
            + iptables_content[last_index:]
        )
        return iptables_content


def _allow_loopback(iptables_content, chain):
    """Allow the loopback device.

    Args:
        iptables_content (str): The contents of the current iptables
        chain (str): The name of the chain for which the loopback rule will be added

    Returns:
        (str): The updated content of iptables
    """
    if re.search(
        "(-A {} -i lo)(.)*(-j ACCEPT)".format(chain),
        iptables_content,
    ):
        logging.info("Loopback interface rule has already been present in the rule set")
        return iptables_content
    filter_table_start = _filter_table_start(iptables_content)
    return (
        iptables_content[:filter_table_start]
        + '-A {} -i lo -m comment --comment "Added by geotables.py" -j ACCEPT\n'.format(
            chain
        )
        + iptables_content[filter_table_start:]
    )


def _get_from_country_code(country_code):
    """Retrieve the IPv4 and IPv6 ranges for the provided country code.

    Args:
        country_code (str): The country code for which the ranges will be retrieved

    Returns:
        ([str], [str]): A tuple of lists (ipv4_blocks, ipv6_blocks)
    """
    try:
        response = urllib3.PoolManager().request(
            "GET",
            "https://stat.ripe.net/data/country-resource-list/data.json?v4_format=prefix&resource={}".format(
                country_code.lower()
            ),
        )
        ripe_json = json.loads(response.data.decode("utf-8"))
    except Exception as e:
        logging.error(
            f"Unable to retrieve list of addresses for country code {country_code} from RIPE: {e}"
        )
        return None, None
    if "data" in ripe_json and "resources" in ripe_json["data"]:
        return (
            ripe_json["data"]["resources"]["ipv4"],
            ripe_json["data"]["resources"]["ipv6"],
        )
    else:
        logging.error("No IP data in response. Malformed or format changed?")
        return None, None


def _load_ranges(country_codes):
    """Load all RIPE IP ranges for the country codes in the provided list.

    Args:
        country_codes ([str]): A list of 2-char country codes (e.g. ["us", "de"])

    Returns:
        ([str], [str]): A tuple of two lists: The aggregated IPv4 and the aggregated IPv6 blocks for the provided country codes
    """
    ipv4 = []
    ipv6 = []
    logging.info("Downloading IP ranges for country codes")
    for country_code in country_codes:
        logging.debug(f"Downloading IP ranges for {country_code}")
        ipv4_country_code, ipv6_country_code = _get_from_country_code(
            country_code=country_code
        )
        if ipv4_country_code:
            logging.debug(
                f"{country_code}: First IPv4 is {ipv4_country_code[0]}, first IPv6 {ipv6_country_code[0]}"
            )
            ipv4.extend(ipv4_country_code)
            ipv6.extend(ipv6_country_code)
        else:
            logging.warning(f"No ranges received for country code {country_code}")
    logging.info(
        "A total of {} IPv4 and {} IPv6 addresses have been downloaded from RIPE".format(
            len(ipv4), len(ipv6)
        )
    )
    return ipv4, ipv6


def _process_list(iptables_content, ip_list, interface, chain):
    """Add the given list of IP blocks to the contents of the iptables dump.

    Args:
        iptables_content (str): The contents of the current iptables
        ip_list ([str]): The list of IP blocks to be whitelisted
        interface (str): The interface for which the rules will be added
        chain (str): The name of the chain for which the rules will be added

    Returns:
        (str): The updated content of iptables
    """
    last_index = _filter_table_start(iptables_content)
    rule_strings = [_ACCEPT_STRING.format(chain, ip, interface) for ip in ip_list]
    rule_string = "\n".join(rule_strings)
    iptables_content = (
        iptables_content[:last_index]
        + rule_string
        + "\n"
        + iptables_content[last_index:]
    )
    return iptables_content


def _back_up_iptables(ipv4=True):
    """Backs up the current iptables contents for processing.

    Args:
        ipv4 (bool, optional): If True, the IPv4 tables will be dumped, otherwise the IPv6 tables. Defaults to True.

    Returns:
        string: Current contents of iptables
    """
    file_path = f"{_IPTABLES_FILENAME}_{datetime.timestamp(datetime.now())}"
    command = (
        f"iptables-save > {file_path}" if ipv4 else f"ip6tables-save > {file_path}"
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        shell=True,
    )
    _, stderr = process.communicate()
    if process.returncode:
        logging.error(
            f"Recieved return code {process.returncode} from process: {stderr}"
        )
        return None
    else:
        with open(file_path, "r") as iptables_handle:
            return iptables_handle.read()


def _restore_iptables(iptables_content, ipv4=True):
    """Restored the modified iptables contents.

    Args:
        ipv4 (bool, optional): If True, the IPv4 tables will be restored, otherwise the IPv6 tables. Defaults to True.

    Returns:
        iptables_content (str): The contents of the current iptables
    """
    file_path = f"{_IPTABLES_FILENAME}_{datetime.timestamp(datetime.now())}"
    with open(file_path, "w") as tmp_handle:
        tmp_handle.write(iptables_content)
    command = (
        f"iptables-restore < {file_path}"
        if ipv4
        else f"ip6tables-restore < {file_path}"
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        shell=True,
    )
    _, stderr = process.communicate()
    if process.returncode:
        logging.error(
            f"Recieved return code {process.returncode} from process: {stderr}"
        )


def block(country_codes, interface, add_only, local_ranges, chains):
    """Block all IPs that do not match the blocks whitelisted for the specified countries.

    Args:
        country_codes ([str]): A list of country codes
        interface (str): The name of the interface for which the rules will be applied
        add_only (bool): If True the whitelist will be added to iptables, but no global drop rule will be created
        local_ranges ([str]): A list of IP ranges to be added to the whitelist
        chains ([str]): The list of chains to which the rules will be added
    """
    ipv4, ipv6 = _load_ranges(country_codes)
    if local_ranges is None:
        ipv4.extend(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"])
    else:
        ipv4.extend(local_ranges)
    # ipv4
    iptables_content = _back_up_iptables()
    for chain in chains:
        ipv4_whitelist = _filter_existing(
            iptables_content, interface, ipv4, chain=chain
        )
        logging.info(
            "Adding {} new IPv4 blocks to the {} chain whitelist".format(
                len(ipv4_whitelist), chain
            )
        )
        iptables_content = _process_list(
            iptables_content=iptables_content,
            ip_list=ipv4_whitelist,
            interface=interface,
            chain=chain,
        )
        if not add_only:
            iptables_content = _allow_loopback(iptables_content, chain=chain)
            iptables_content = _add_default_drop(
                iptables_content=iptables_content, interface=interface, chain=chain
            )
    _restore_iptables(iptables_content)
    # ipv6
    ip6tables_content = _back_up_iptables(ipv4=False)
    for chain in chains:
        ipv6_whitelist = _filter_existing(
            iptables_content, interface, ipv6, chain=chain
        )
        logging.info(
            "Adding {} new IPv6 blocks to the {} chain whitelist".format(
                len(ipv6_whitelist), chain
            )
        )
        iptables_content = _process_list(
            iptables_content=iptables_content,
            ip_list=ipv6_whitelist,
            interface=interface,
            chain=chain,
        )
        if not add_only:
            iptables_content = _allow_loopback(iptables_content, chain=chain)
            iptables_content = _add_default_drop(
                iptables_content=iptables_content,
                interface=interface,
                chain=chain,
                ipv4=False,
            )
    # TODO add readme
    # TODO fix unit tests
    _restore_iptables(ip6tables_content, ipv4=False)


def command_line():
    parser = argparse.ArgumentParser(
        description="Set up geoblocking using iptables and whitelists."
    )
    parser.add_argument(
        "country_codes",
        type=str,
        nargs="+",
        help="A (list of) country code(s). Example: de us uk",
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        required=True,
        help="The interface for which the rules shall be created",
    )
    parser.add_argument(
        "-c",
        "--chains",
        nargs="+",
        default=["INPUT"],
        help="The list of chains to which the rules will be added",
    )
    parser.add_argument(
        "-a",
        "--add_only",
        action="store_true",
        default=False,
        help="Only add the whitelisted IPs, not not drop everything else",
    )
    parser.add_argument(
        "-w",
        "--whitelisted_local",
        nargs="*",
        type=str,
        help="Add local ranges to the whitelist. If no additional parameters are provided, all local ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10) will be whitelisted",
    )
    parser.add_argument(
        "-l",
        "--log_level",
        choices=logging._nameToLevel,
        default=logging.INFO,
        help="The log level",
    )
    parser.add_argument(
        "-lf",
        "--log_file",
        type=str,
        default="geotables.log",
        help="The path to the log file",
    )

    args = parser.parse_args()
    logging.getLogger().setLevel(level=logging.getLevelName(args.log_level))
    formatter = logging.Formatter(
        fmt="%(levelname)-9s | %(asctime)s.%(msecs)03d | (%(filename)s:%(lineno)d) | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(lambda record: record.levelno <= logging.INFO)
    logging.getLogger().addHandler(stdout_handler)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    stderr_handler.addFilter(lambda record: record.levelno > logging.INFO)
    logging.getLogger().addHandler(stderr_handler)

    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    block(
        args.country_codes,
        args.interface,
        args.add_only,
        args.whitelisted_local,
        args.chains,
    )


if __name__ == "__main__":
    command_line()
