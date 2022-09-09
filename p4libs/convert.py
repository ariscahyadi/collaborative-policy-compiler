# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import binascii
import math
import re
import socket
import ipaddress
import codecs

'''
This package contains several helper functions for encoding to and decoding from byte strings:
- integers
- IPv4 address strings
- Ethernet address strings
'''

mac_pattern = re.compile('^([\da-fA-F]{2}:){5}([\da-fA-F]{2})$')


def matchesMac(mac_addr_string):
    return mac_pattern.match(mac_addr_string) is not None


def encodeMac(mac_addr_string):
    return binascii.unhexlify(mac_addr_string.replace(':', ''))


def decodeMac(encoded_mac_addr):
    return ':'.join(chr(s).encode('latin-1').hex() for s in encoded_mac_addr)


ip_pattern = re.compile('^(\d{1,3}\.){3}(\d{1,3})$')


def matchesIPv4(ip_addr_string):
    return ip_pattern.match(ip_addr_string) is not None

ip6_pattern = re.compile('^([0-9A-Fa-f]{0,4}:){2,7}([0-9A-Fa-f]{1,4}$|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})$')

def matchesIPv6(ip_addr_string):
    return ip6_pattern.match(ip_addr_string) is not None

def encodeIPv4(ip_addr_string):
    return socket.inet_aton(ip_addr_string)

def decodeIPv4(encoded_ip_addr):
    return socket.inet_ntoa(encoded_ip_addr)


def encodeIPv6(ip_addr_string):
    return socket.inet_pton(socket.AF_INET6, ip_addr_string)


def decodeIPv6(encoded_ip_addr):
    return socket.inet_ntop(socket.AF_INET6, encoded_ip_addr)


def bitwidthToBytes(bitwidth):
    return int(math.ceil(bitwidth / 8.0))


def encodeNum(number, bitwidth):
    byte_len = bitwidthToBytes(bitwidth)
    num_str = '%x' % number
    if number >= 2 ** bitwidth:
        raise Exception(
            "Number, %d, does not fit in %d bits" % (number, bitwidth))
    return binascii.unhexlify(('0' * (byte_len * 2 - len(num_str)) + num_str))


def decodeNum(encoded_number):
    return int(codecs.encode(encoded_number, 'hex'), 16)


def encode(x, bitwidth):
    'Tries to infer the type of `x` and encode it'
    byte_len = bitwidthToBytes(bitwidth)
    if (type(x) == list or type(x) == tuple) and len(x) == 1:
        x = x[0]
    encoded_bytes = None
    if type(x) == str:
        if matchesMac(x):
            encoded_bytes = encodeMac(x)
        elif matchesIPv4(x):
            encoded_bytes = encodeIPv4(x)
        elif matchesIPv6(x):
            encoded_bytes = encodeIPv6(x)
        else:
            # Assume that the string is already encoded
            encoded_bytes = x
    elif type(x) == int:
        encoded_bytes = encodeNum(x, bitwidth)
    elif type(x) == bytes:
        encoded_bytes = x
    else:
        raise Exception("Encoding objects of %r is not supported" % type(x))
    print(len(encoded_bytes))
    print(byte_len)
    assert (len(encoded_bytes) == byte_len)
    return encoded_bytes


if __name__ == '__main__':
    # TODO These tests should be moved out of main eventually
    mac = "aa:bb:cc:dd:ee:ff"
    enc_mac = encodeMac(mac)
    assert (enc_mac == bytes('\xaa\xbb\xcc\xdd\xee\xff', 'raw_unicode_escape'))
    dec_mac = decodeMac(enc_mac)
    assert (mac == dec_mac)

    ip = "10.0.0.1"
    enc_ip = encodeIPv4(ip)
    assert (enc_ip == bytes('\x0a\x00\x00\x01', 'raw_unicode_escape'))
    dec_ip = decodeIPv4(enc_ip)
    assert (ip == dec_ip)

    ip6 = "2001:0db8:bbbb:0000:0000:0000:0000:0001"
    enc_ip6 = encodeIPv6(ip6)
    assert (enc_ip6 == bytes(' \x01\r\xb8\xbb\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
                             'raw_unicode_escape'))
    dec_ip6 = decodeIPv6(enc_ip6)
    assert (ip6 == ipaddress.ip_address(dec_ip6).exploded)

    num = 1337
    byte_len = 5
    enc_num = encodeNum(num, byte_len * 8)
    assert (enc_num == bytes('\x00\x00\x00\x059', 'raw_unicode_escape'))
    dec_num = decodeNum(enc_num)
    assert (num == dec_num)

    assert (matchesIPv4('10.0.0.1'))
    assert (not matchesIPv4('10.0.0.1.5'))
    assert (not matchesIPv4('1000.0.0.1'))
    assert (not matchesIPv4('10001'))

    assert (matchesIPv6('2001:0db8:bbbb:0000:0000:0000:0000:0001'))
    assert (not matchesIPv4('20010db8:bbbb0000:00000000:00000001'))
    assert (not matchesIPv4('20010db8bbbb00000000000:00000001'))

    assert (encode(mac, 6 * 8) == enc_mac)
    assert (encode(ip, 4 * 8) == enc_ip)
    assert (encode(ip6, 16 * 8) == enc_ip6)
    assert (encode(num, 5 * 8) == enc_num)
    assert (encode((num,), 5 * 8) == enc_num)
    assert (encode([num], 5 * 8) == enc_num)

    num = 256
    byte_len = 2
    try:
        enc_num = encodeNum(num, 8)
        raise Exception("expected exception")
    except Exception as e:
        print(e)
