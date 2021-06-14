"""
Utility for formatting and checking the policy criterion/criteria
"""


def convert_any_to_zero(criteria):
    """
    Function to convert 'any' criteria into 0 value
    :param criteria: criteria with any or 0 value
    :return: criteria: with only 0 value
    """

    if criteria == "any" or criteria == "0":
        criteria = "0"

    return criteria


def convert_name_to_protocol_number(criteria):
    """
    Function to convert 'tcp' or 'udp' criteria into 17 or 6 value
    :param criteria: criteria with 'tcp' or 'udp' or 17 or 6 value
    :return: criteria: with only 17 and 6 value
    """

    if criteria == "tcp" or criteria == "6":
        criteria = "6"
    elif criteria == "udp" or criteria == "17":
        criteria = "17"
    else:
        print("Protocol Error")

    return criteria


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
