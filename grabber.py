#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
from scapy.all import *
from scapy.layers.tls.extensions import TLS_Ext_SupportedGroups, TLS_Ext_SupportedPointFormat, \
    TLS_Ext_SignatureAlgorithms, TLS_Ext_Heartbeat, TLS_Ext_Padding
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS

logger = logging.getLogger(__name__)

class SROSPolicy:
    """
    Class for representing a SROS Policy, containing the possible types for it, the value and its permissions.
    """
    TYPE_SUBSCRIPTABLE_TOPICS = 'Subscriptable topics'
    TYPE_PUBLISHABLE_TOPICS = 'Publishable topics'
    TYPE_EXECUTABLE_SVCS = 'Executable services'
    TYPE_READABLE_PARAMS = 'Readable parameters'
    TYPE_UNKNOWN = 'Unknown'
    POLICY_ALLOWED = True
    POLICY_DENIED = False

    def __init__(self):
        self.type = SROSPolicy.TYPE_UNKNOWN
        self.values = []
        self.permissions = SROSPolicy.POLICY_DENIED

    def __repr__(self):
        return 'Type: {}, Values: {}, Permission: {}'.format(self.type, self.values, self.permissions)


async def get_sros_certificate(address, port, timeout=3):
    """
    Function to connect to a SROS Node, simulate the TLS handshake, and get it's server certificate on the process.
    :param address: Address of the node.
    :param port: Port of the node.
    :param timeout: Timeout for the connection.
    :return: A tuple containing the address, port and certificate if found, otherwise,
    a tuple containing address, port and None.
    """
    client_hello = TLS(version='TLS 1.0', msg=TLSClientHello(
        ciphers=[49200, 49196, 49202, 49198, 49199, 49195, 49201, 49197, 165, 163, 161, 159, 164, 162, 160, 158, 49192,
                 49188, 49172, 49162, 49194, 49190, 49167, 49157, 107, 106, 105, 104, 57, 56, 55, 54, 49191, 49187,
                 49171, 49161, 49193, 49189, 49166, 49156, 103, 64, 63, 62, 51, 50, 49, 48, 136, 135, 134, 133, 69, 68,
                 67, 66, 49170, 49160, 49165, 49155, 22, 19, 16, 13, 157, 156, 61, 53, 60, 47, 132, 65, 10, 255],
        comp=[0],
        gmt_unix_time=12345566,
        ext=[TLS_Ext_SupportedGroups(groups=[23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10]),
             TLS_Ext_SupportedPointFormat(ecpl=[0, 1, 2]),
             TLS_Ext_SignatureAlgorithms(
                 sig_algs=[1537, 1538, 1539, 1281, 1282, 1283, 1025, 1026, 1027, 769, 770, 771, 513, 514, 515]),
             TLS_Ext_Heartbeat(heartbeat_mode=1),
             TLS_Ext_Padding(padding=212 * b'\x00')]))

    tls_header = b'\x16\x03\x03'
    server_hello_done = b'\x0e\x00\x00\x00'
    received_data = b''
    is_sros = True
    writer = None
    try:
        conn = asyncio.open_connection(str(address), port, loop=asyncio.get_event_loop())
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.write(bytes(client_hello))
        await writer.drain()
        while received_data[-4:] != server_hello_done:
            received_data += await asyncio.wait_for(reader.read(1024), timeout=3)
            if received_data[:3] != tls_header:
                is_sros = False
                break
    except Exception as e:
        logger.error('[-] Error connecting to host ' + str(address) + ': ' + str(e) + '\n\tNot a SROS host')
        return address, port, None
    else:
        if is_sros:
            server_hello = TLS(received_data)
            cert = server_hello.payload.msg[0].certs[0][1]
            logger.warning('[+] SROS host found!!!')
            return address, port, cert
    finally:
        if writer:
            writer.close()
            if sys.version_info >= (3, 7, 0):
                await writer.wait_closed()
    return address, port, None


def get_policies(cert):
    """
    Get the related policies from an input SROS Node certificate.
    :param cert: Certificate in X509 format.
    :return: List containing all policies as instances of :class:`aztarna.sros.helpers.SROSPolicy`
    """
    policies = []
    try:
        extensions = cert.tbsCertificate.extensions
        policies_extension = list(filter(lambda ext: ext.extnID.val == '2.5.29.32', extensions))[0]
        for cert_policy in policies_extension.extnValue.certificatePolicies:
            id = cert_policy.policyIdentifier.val
            policy = SROSPolicy()
            if id[-3] == '1':
                policy.type = SROSPolicy.TYPE_SUBSCRIPTABLE_TOPICS
            elif id[-3] == '2':
                policy.type = SROSPolicy.TYPE_PUBLISHABLE_TOPICS
            elif id[-3] in ['3', '6']:
                policy.type = SROSPolicy.TYPE_UNKNOWN
            elif id[-3] == '4':
                policy.type = SROSPolicy.TYPE_EXECUTABLE_SVCS
            elif id[-3] == '5':
                policy.type = SROSPolicy.TYPE_READABLE_PARAMS

            if id[-1] == '1':
                policy.permission = SROSPolicy.POLICY_ALLOWED
            else:
                policy.permission = SROSPolicy.POLICY_DENIED

            for qualifier in cert_policy.policyQualifiers:
                policy.values.append(qualifier.qualifier.val)
            policies.append(policy)
    except Exception:
        logger.warning('\t\tException when capturing the certificate policies')
    return policies