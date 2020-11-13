import socket
import google.protobuf.text_format
import p4libs.p4runtime_pb2 as p4runtime_pb2
import p4libs.helper as helper
import math
import codecs


def decodeIPv4(encoded_ip_addr):
    """
    Function to convert IP address to string format
    :param encoded_ip_addr: IP address in IP format
    :return: string of IP address
    """
    return socket.inet_ntoa(encoded_ip_addr)


def encodeIPv4(ip_addr_string):
    """
    Fucntio to convert IP address from string format
    :param ip_addr_string: string of IP address
    :return: IP address
    """
    return socket.inet_aton(ip_addr_string)


def bitwidthToBytes(bitwidth):
    """
    Convert number of bits into bytes
    :param bitwidth: total number of bits
    :return: bytes
    """
    return int(math.ceil(bitwidth / 8.0))


def encodeNum(number, bitwidth):
    """
    Function to encode integer number to hexadecimal format
    :param number: integer value
    :param bitwidth: total number of bit to encode
    :return:
    """
    byte_len = bitwidthToBytes(bitwidth)
    num_str = '%x' % number
    if number >= 2 ** bitwidth:
        raise Exception("Number, %d, does not fit in %d bits" % (number, bitwidth))
    return codecs.decode(('0' * (byte_len * 2 - len(num_str)) + num_str), 'hex_codec')


def decodeNum(encoded_number):
    """
    Function to decode hexadecimal into integer value
    :param encoded_number: hexadecimal value
    :return: integer value
    """
    temp = codecs.encode(encoded_number, 'hex_codec')
    return int(temp, 16)


def rule_table_builder(protobuf_input):
    """
    Function to read P4 runtime's response of rules query
    :param protobuf_input: response in protobuf format
    :return: P4 table of protobuf message
    """
    p4table = p4runtime_pb2.TableEntry()
    with open(protobuf_input) as p4runtime_f:
        google.protobuf.text_format.Merge(p4runtime_f.read(), p4table)
    return p4table


def rule_parser(p4table):
    """
    Function to parse the P4 rule in the P4 table into policy criterion
    :param p4table: P4 table contains P4 rules
    :return: policy criterion
    """
    criterion = ""
    for entry in p4table.match:
        i = 0
        field = list()
        for item in helper.P4InfoHelper.get_match_field_value(entry, entry):
            field.append(item)
            i = i + 1
        if i <= 1:
            criterion = criterion + str(field[0]) + ","
        else:
            criterion = criterion + str(decodeIPv4(field[0])) \
                        + "/" + str(field[1]) + ","
    return criterion[:-1]


def rule_to_policy_builder(criterion):
    """
    Function to build the multiple policy criterion from P4 rules in the
    P4 table.
    :param criterion: policy criterion from P4 rules
    :return: policy from existing P4 rules
    """

    i = 0
    entry = "accept"
    policy = []

    for criteria in criterion.split(","):
        i = i + 1
        entry = entry + "," + criteria
        if i == 5:
            policy.append(entry)
            entry = "accept"
            i = 0

    for index in range(len(policy)):
        print("| %d | %s |" % (index, policy[index]))

    return list(map(lambda x: [x], policy))
