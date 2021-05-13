#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from scapy.all import *
from scapy.layers.tls.extensions import TLS_Ext_SupportedGroups, TLS_Ext_SupportedPointFormat, \
    TLS_Ext_SignatureAlgorithms, TLS_Ext_Heartbeat, TLS_Ext_Padding
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import socket

load_layer('tls')
logging.basicConfig(level=logging.INFO, format='%(asctime)s :: %(levelname)s :: %(message)s')

def get_tls_certificate(address, port):
    target = (address, port)

    # create TLS Handshake / Client Hello
    p = TLS(version='TLS 1.0', msg=TLSClientHello(
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

    try:
        # TCP Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(target)

        # p.show()
        logging.info("sending TLS Client Hello")
        s.sendall(bytes(p))
        resp = s.recv(1024 * 8)
        if resp[:3] != tls_header:
            logging.error("no Server Hello recived")
            exit(1)
        # parse received data
        logging.info("recived Server Hello")
        server_hello = TLS(resp)
        # get certificate from Server Hello Response
        cert = server_hello.payload.msg[0].certs[0][1]
        logging.info(cert)
        name = cert.subject['commonName']
        organization = cert.subject['organizationName']
        logging.info(name)
        logging.info(organization)
    except Exception as error:
        logging.error(f"Error ocurred: {error} ")
    finally:
        s.close()

if __name__ == '__main__':
    if len(sys.argv) <= 2:
        logging.warning("USAGE: <host> <port>")
        exit(1)
    
    get_tls_certificate(sys.argv[1], int(sys.argv[2]))