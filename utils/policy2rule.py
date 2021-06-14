import p4libs.helper as helper
import utils.utils as utils
import ipaddress


"""
This package is used to:
- aggregate the policy
- group the policy based on the similar header
- optimize the policy to remove overlapping (port number or IP address)
- generate rules based on the optimized policy
"""


def rule_generator(ipProtocol, srcPort, dstPort, srcAddr, dstAddr):
    """
    Function to generate P4 rules in P4 runtime stream format from a single
    policy entry.
    :param ipProtocol: protocol type either UDP or TCP
    :param srcPort: source UDP/TCP port
    :param dstPort: destination UDP/TCP port
    :param srcAddr: source IPv4 Address
    :param dstAddr: destination IPv4 Address
    :return: table_entry: P4 rule entry
    """

    p4info_help = helper.P4InfoHelper("data/firewall.p4.p4info.txt")
    srcAddr = srcAddr.split("/")
    dstAddr = dstAddr.split("/")
    ipProtocol = utils.convert_name_to_protocol_number(ipProtocol)
    srcPort = utils.convert_any_to_zero(srcPort)
    dstPort = utils.convert_any_to_zero(dstPort)
    table_entry = p4info_help.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.protocol": int(ipProtocol),
            "hdr.tcp.srcPort": int(srcPort),
            "hdr.tcp.dstPort": int(dstPort),
            "hdr.ipv4.srcAddr": (srcAddr[0], int(srcAddr[1])),
            "hdr.ipv4.dstAddr": (dstAddr[0], int(dstAddr[1])),
        },
        action_name="MyIngress.ipv4_forward",
        action_params={"dstAddr": "00:00:00:00:00:01", "port": 1},
    )
    return str(table_entry)


def policy_to_rule(policy):
    """
    Function to generate P4 rules from multiple entries of policy criterion
    :param policy: aggregated and optimized policy
    """

    criterion = [item for sublist in policy for item in sublist]
    rules = ""

    for index in range(len(criterion)):
        criteria = criterion[index].split(",")
        rule = rule_generator(
            criteria[1], criteria[2], criteria[3], criteria[4], criteria[5]
        )
        rules = rules + rule
        print(rules)

    return rules


def aggregate_ip_address(src_address, dst_address):
    """
    Function to aggregate overlapping IP addresses into subnet
    :param src_address: source IPv4 addresses
    :param dst_address: destination IPv4 addresses
    :return: aggregated and optimized source and destination IPv4 addresses
    """

    net_src = [ipaddress.ip_network(_ip) for _ip in src_address]
    cidr_src = ipaddress.collapse_addresses(net_src)
    aggregate_src_address = list()
    aggregate_dst_address = list()

    for overlap_ip1 in cidr_src:
        overlap_ips2 = list()
        for i in range(len(src_address)):
            if ipaddress.ip_network(src_address[i]).overlaps(overlap_ip1):
                overlap_ips2.append(ipaddress.ip_network(dst_address[i]))
        optimize_overlap_ip2 = ipaddress.collapse_addresses(overlap_ips2)

        for ip2 in optimize_overlap_ip2:
            aggregate_src_address.append(overlap_ip1)
            aggregate_dst_address.append(ip2)

    return aggregate_src_address, aggregate_dst_address


def check_duplicate_header(header):
    """
    Function to check the duplicated IP header (protocol, source and
    destination port number)
    :param header:
    :return: duplicated header
    """

    duplicate_header = dict()
    index = 0
    for item in header:
        if header in duplicate_header:
            duplicate_header[item][0] += 1
            duplicate_header[item][1].append(index)
        else:
            duplicate_header[item] = [1, [index]]
        index += 1

    duplicate_header = {
        key: value for key, value in duplicate_header.items() if value[0] > 1
    }
    return duplicate_header


def policy_optimizer(aggregate_policy):
    """
    Function to check the duplicated header and overlapping IP addresses, and
    then optimize it
    :param aggregate_policy:
    :return: new and optimized policy
    """

    tcp_header = list()
    src_address = list()
    dst_address = list()

    criterion = [item for sublist in aggregate_policy for item in sublist]

    for index in range(len(criterion)):
        criteria = criterion[index].split(",")
        header = (
            utils.convert_name_to_protocol_number(criteria[1])
            + ","
            + utils.convert_any_to_zero(criteria[2])
            + ","
            + utils.convert_any_to_zero(criteria[3])
        )
        tcp_header.append(header)
        src_address.append(criteria[4])
        dst_address.append(criteria[5])

    duplicate_header = dict()
    index = 0
    for header in tcp_header:
        if header in duplicate_header:
            duplicate_header[header][0] += 1
            duplicate_header[header][1].append(index)
        else:
            duplicate_header[header] = [1, [index]]
        index += 1

    duplicate_tcp_header = {
        key: value for key, value in duplicate_header.items() if value[0] > 1
    }

    new_policy = [
        criterion[value[1][0]] for value in duplicate_header.values() if value[0] == 1
    ]


    for key, value in duplicate_tcp_header.items():
        tcp_header_group = list()
        src_address_group = list()
        dst_address_group = list()
        agg_src_address = list()
        agg_dst_address = list()
        tcp_header_group.append(key)
        for item in value[1]:
            src_address_group.append(src_address[item])
            dst_address_group.append(dst_address[item])

        new_src_address, new_dst_address = aggregate_ip_address(
            src_address_group, dst_address_group
        )
        agg_src_address.append(new_src_address)
        agg_dst_address.append(new_dst_address)

        for index in range(len(new_src_address)):
            new_criterion = (
                "accept,"
                + key
                + ","
                + str(ipaddress.ip_network(new_src_address[index]))
                + ","
                + str(ipaddress.ip_network(new_dst_address[index]))
            )
            new_policy.append(new_criterion)

    for index in range(len(new_policy)):
        print("| %d | %s |" % (index, new_policy[index]))
    return new_policy
