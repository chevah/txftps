# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
An example FTPES/FTPIS server with minimal user authentication.
"""

import sys
import os
sys.path.append(os.path.abspath('.'))

from twisted.protocols.ftp import FTPRealm
from twisted.python import log
from twisted.cred.portal import Portal
from twisted.internet import reactor
from twisted.internet.ssl import DefaultOpenSSLContextFactory

from chevah.txftps.factory import FTPFactory, FTPSIFactory
from chevah.txftps.checkers import InMemoryPassword, SSLCertificateChecker

log.startLogging(sys.stdout)

# Users folders are in /tmp. For 'test_user' create folder '/tmp/test_user'.
portal = Portal(
    FTPRealm(anonymousRoot=None, userHome='/tmp'),
    [InMemoryPassword([('test_user', 'password')]), SSLCertificateChecker()],
    )

ssl_context_factory = DefaultOpenSSLContextFactory(
    'example/server-cert-and-key.pem',
    'example/server-cert-and-key.pem',
    )

factory_explicit = FTPFactory()
factory_explicit.ssl_enabled = True
factory_explicit.ssl_command_required = True
factory_explicit.ftps_force_secured_authentication = True
factory_explicit.enable_password_authentication = True
factory_explicit.enable_ssl_certificate_authentication = True
factory_explicit.portal = portal
factory_explicit.ssl_context_factory = ssl_context_factory
reactor.listenTCP(10021, factory_explicit)

factory_implicit = FTPSIFactory()
factory_implicit.portal = portal
factory_implicit.ssl_context_factory = ssl_context_factory
reactor.listenTCP(10990, factory_implicit)

reactor.run()
