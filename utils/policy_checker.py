import ipaddress
import utils.utils as utils


def inter_policy_matching(policy_one, policy_two):
    """
    Function to match each criteria between two policies
    :param policy_one: first policy input
    :param policy_two: second policy input
    :return: intersection set of the policies
    """

    criterion_one = [item for sublist in policy_one for item in sublist]
    criterion_two = [item for sublist in policy_two for item in sublist]

    return set(criterion_one).intersection(set(criterion_two))


def str_to_bin(ip_address):
    """
    Function to convert IP address from string into binary format
    :param ip_address: IP address in string
    :return: IP address in binary
    """

    return "{:032b}".format(int(ipaddress.IPv4Network(ip_address).network_address))


def xor_operation(ip_bit_one, ip_bit_two):
    """
    :param ip_bit_one: first IP in bit array
    :param ip_bit_two: second IP bit array
    :return:
    """

    for index in range(0, 31):
        bin_one = int(ip_bit_one[index], 2)
        bin_two = int(ip_bit_two[index], 2)
        if (bin_one ^ bin_two) == int("1", 2):
            break

    if index == 30:
        return ""
    else:
        return ip_bit_one[0:index]


def ip_address_overlap_check(address_list, index_list):
    """
    Function to check an overlapping bit IP address
    :param address_list: list of IPv4 (source/destination) address
    :param index_list: policy index where the IP is exist
    :return:
    """

    address_length = len(address_list)
    for j in range(address_length):
        for k in range(address_length):
            if j != k:
                ipaddr_one = ipaddress.ip_network(address_list[j])
                ipaddr_two = ipaddress.ip_network(address_list[k])
                index_one = index_list[j]
                index_two = index_list[k]
                if ipaddr_one.overlaps(ipaddr_two):
                    if (
                        str(ipaddr_one.netmask)
                        and str(ipaddr_two.netmask) != "255.255.255.255"
                    ):
                        print(
                            "IP address %s and %s are overlap, so policy "
                            "criterion %s and %s are overlap"
                            % (ipaddr_one, ipaddr_two, index_one, index_two)
                        )


def intra_policy_check(site_policy, matched_policy):
    """
    Function to check policy in a single site
    :param site_policy: site policy to be checked
    :param matched_policy: matching policy between two sites
    :return: only valid policy (without overlapping and invalid address)
    """

    from itertools import product

    class Policy:
        action: str
        header: str
        ip_src: ipaddress.IPv4Network
        ip_dst: ipaddress.IPv4Network

        def __init__(self, policy):
            criteria = policy.split(",")

            self.action = criteria[0]
            self.header = ",".join(
                [
                    utils.convert_name_to_protocol_number(criteria[1]),
                    utils.convert_any_to_zero(criteria[2]),
                    utils.convert_any_to_zero(criteria[3]),
                ]
            )
            self.ip_src = ipaddress.IPv4Network(criteria[4])
            self.ip_dst = ipaddress.IPv4Network(criteria[5])

        def __str__(self):
            return ",".join(
                [self.action, self.header, str(self.ip_src), str(self.ip_dst)]
            )

    matched = [Policy(policy) for policy in matched_policy]
    site = [Policy(item) for sublist in site_policy for item in sublist]

    valid_policy = list()

    for policy_s, policy_m in product(site, matched):
        if policy_s.header != policy_m.header:
            continue

        if policy_m.ip_src.overlaps(policy_s.ip_src):
            if policy_m.ip_src != policy_s.ip_src:
                print("%s is overlap with %s" % (policy_m.ip_src, policy_s.ip_src))
                continue

        if policy_m.ip_dst.overlaps(policy_s.ip_dst):
            if policy_m.ip_dst != policy_s.ip_dst:
                print("%s is overlap with %s" % (policy_m.ip_dst, policy_s.ip_dst))
                continue

        valid_policy.append(str(policy_s))

    return valid_policy


def read_policy_input(filename):
    """
    Read policy from file input
    :param filename: the name of file contains the policy
    :return: list of policy
    """

    with open(filename) as policy_input:
        policy = []
        for criterion in policy_input:
            criterion = criterion.strip()
            policy.append(criterion)

        return policy
