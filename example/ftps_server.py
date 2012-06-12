# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
An example FTP server with minimal user authentication.
"""

import sys
import os
sys.path.append(os.path.abspath('.'))

from twisted.protocols.ftp import FTPRealm
from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.internet import reactor

from txftps.factory import FTPSFactory
from txftps.checkers import SSLCertificateChecker

portal = Portal(
    FTPRealm('./example'),
    [FilePasswordDB("example/pass.dat"), SSLCertificateChecker()],
    )

factory = FTPSFactory(
    portal,
    certificate_path='example/server-cert-and-key.pem',
    key_path=None,  # certificate contains they key.
    ca_path=None,  # 'example/ca.pem'
    crl_path=None,  # 'example/crl.pem'
    allowed_methods='sslv3 tlsv1',
    cipher_list='ALL',
    )

factory.ssl_enabled = True
factory.ssl_command_required = False
factory.ssl_data_required = False
factory.enable_password_authentication = True
factory.enable_ssl_certificate_authentication = True

reactor.listenTCP(10021, factory)
reactor.run()
