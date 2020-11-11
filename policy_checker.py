import ipaddress
import utils


def inter_policy_matching(policy_one, policy_two):
    """Function to match each criteria between two policies
    :param policy_one: first policy input
    :param policy_two: second policy input
    :return: intersection set of the policies
    """

    criterion_one = [item for sublist in policy_one for item in sublist]
    criterion_two = [item for sublist in policy_two for item in sublist]

    return set(criterion_one).intersection(set(criterion_two))


def str_to_bin(ip_address):
    """Function to convert IP address from string into binary format
    :param ip_address: IP address in string
    :return: IP address in binary
    """

    return '{:032b}'.format(int(ipaddress.IPv4Network(ip_address)
                                .network_address))


def xor_operation(ip_bit_one, ip_bit_two):
    """
    :param ip_bit_one: first IP in bit array
    :param ip_bit_two: second IP bit array
    :return:
    """

    for index in range(0, 31):
        bin_one = int(ip_bit_one[index], 2)
        bin_two = int(ip_bit_two[index], 2)
        if (bin_one ^ bin_two) == int('1', 2):
            break

    if index == 30:
        return ""
    else:
        return ip_bit_one[0:index]


def ip_address_overlap_check(address_list, index_list):
    """ Function to check an overlapping bit IP address
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
                    if str(ipaddr_one.netmask) and str(ipaddr_two.netmask) \
                            != "255.255.255.255":
                        print("IP address %s and %s are overlap, so policy "
                              "criterion %s and %s are overlap"
                              % (ipaddr_one, ipaddr_two,index_one, index_two))

    #for j in range(address_length):
    #    for k in range(address_length):
    #        if j != k:
    #            if xor_operation(str_to_bin(address_list[j]),
    #                             str_to_bin(address_list[k])) != "":
    #                print("Policy criterion %s and %s are overlap"
    #                      % (address_list[j], address_list[k]))


#def intra_policy_check(policy_one):
#   """Function to check an overlapping IP address in the policy
#    :param policy_one: First policy
#    :return: Yes or No
#    """

#    src_address = list()
#    dst_address = list()
#    criterion_index_src_addr = list()
#    criterion_index_dst_addr = list()

#    criterion = [item for sublist in policy_one for item in sublist]

#    for index in range(len(criterion)):
#        print("| %d | %s |" % (index, criterion[index]))

#    print("")
#    print("Checking the invalid address .....")

#    for index in range(len(criterion)):
#        criteria = criterion[index].split(',')
#        if criteria[4] != "0.0.0.0/0":
#            src_address.append(criteria[4])
#            criterion_index_src_addr.append(index)
#        else:
#            print("Found invalid address %s in policy criterion %d"
#                  % (criteria[4], index))

#        if criteria[5] != "0.0.0.0/0":
#            dst_address.append(criteria[5])
#            criterion_index_dst_addr.append(index)
#        else:
#            print("Found invalid address %s in policy criterion %d"
#                  % (criteria[5], index))

#    print("")
#    print("Checking the overlapping source address .....")
#    ip_address_overlap_check(src_address, criterion_index_src_addr)
#    print("")
#    print("Checking the overlapping destination address .....")
#    ip_address_overlap_check(dst_address, criterion_index_dst_addr)
#    print("")


def intra_policy_check(site_policy, matched_policy):

    site_criterion = [item for sublist in site_policy for item in sublist]
    matched_header = list()
    matched_src_addr = list()
    matched_dst_addr = list()
    valid_policy = list()

    for index in range(len(matched_policy)):
        criteria = matched_policy[index].split(',')
        header = utils.convert_name_to_protocol_number(criteria[1]) + "," \
            + utils.convert_any_to_zero(criteria[2]) + "," \
            + utils.convert_any_to_zero(criteria[3])
        matched_header.append(header)
        matched_src_addr.append(criteria[4])
        matched_dst_addr.append(criteria[5])

    for index in range(len(site_criterion)):

        criteria = site_criterion[index].split(',')
        header = utils.convert_name_to_protocol_number(criteria[1]) + "," \
            + utils.convert_any_to_zero(criteria[2]) + "," \
            + utils.convert_any_to_zero(criteria[3])

        for index2 in range(len(matched_policy)):

            if str(header) == matched_header[index2]:
                ip_src = criteria[4]
                ip_dst = criteria[5]

                if ip_src == "0.0.0.0/0" or ip_dst == "0.0.0.0/0":
                    print("One of the %s or %s is invalid" % (ip_src, ip_dst))
                    continue
                if ipaddress.IPv4Network(matched_src_addr[index2]) \
                        not in ipaddress.IPv4Network(ip_src):

                    if str(ipaddress.ip_network(ip_src).netmask) \
                            != "255.255.255.255":
                        print("%s is overlap with %s"
                              % (matched_src_addr[index2], ip_src))
                        continue

                if ipaddress.IPv4Network(matched_dst_addr[index2]) \
                        not in ipaddress.IPv4Network(ip_dst):

                    if str(ipaddress.ip_network(ip_dst).netmask) \
                            != "255.255.255.255":
                        print("%s is overlap with %s"
                              % (matched_dst_addr[index], ip_dst))
                        continue

                valid_policy.append(','.join(criteria))

    return valid_policy







