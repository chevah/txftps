# Copyright (c) 2010 Adi Roiban.
# See LICENSE for details.
'''FTPS factory.'''

from __future__ import with_statement
from OpenSSL import SSL
import time

from twisted.protocols.ftp import (
    FTPFactory,
    )

from txftps.logger import _, log
from txftps.protocol import FTPProtocol
from txftps.ssl import ServerSSLContextFactory


class FTPSFactory(FTPFactory, object):
    '''Factory for creating FTP protocol instances.'''

    protocol = FTPProtocol

    def __init__(self, portal, certificate_path, key_path=None,
            ca_path=None, crl_path=None,
            allowed_methods='sslv3 tlsv1', cipher_list='ALL'):
        self.key_path = key_path
        self.certificate_path = certificate_path
        self.ca_path = ca_path
        self.crl_path = crl_path
        self.allowed_methods = allowed_methods
        self.cipher_list = cipher_list

        self.allowAnonymous = False
        self.welcomeMessage = 'Hello to txftps.'
        self.passivePortRange = xrange(0, 0)
        self.ssl_context = None

        self.ssl_enabled = True
        self.ssl_command_required = True
        self.ssl_data_required = True
        self.enable_password_authentication = True
        self.enable_ssl_certificate_authentication = True

        self._validateConfiguration()
        self.configureSSL()

        super(FTPSFactory, self).__init__(portal)

    def _validateConfiguration(self):
        '''Check that the current configuration is valid.'''
        if (not self.enable_password_authentication and
            not self.enable_ssl_certificate_authentication):
            log(10017, _(
                u'No authentication method enabled. Users will not be able '
                u'to authenticate agains the FTP/FTPS service. Please enable '
                u'one of the supported authentication methods.'))
            raise AssertionError

        if (not self.enable_password_authentication and
            not self.ssl_enabled):
            log(10018, _(
                u'Password based authentication must be enabled when FTPS '
                u'is not enabled.'))
            raise AssertionError

    def configureSSL(self):
        '''Initialize SSLContext and check that input files can be used.'''

        if not self.ssl_enabled:
            '''Don't initialize the SSL context if FTPS is not enabled.'''
            return

        if self.ssl_context is not None:
            raise AssertionError('SSL/TLS context was already initialized.')

        if self.certificate_path is None:
            log(10032,
                _('At least "server_ftps_ssl_certificate" file must be '
                'specified.'))
            raise AssertionError

        if self.key_path is None:
            self.key_path = self.certificate_path

        try:
            self.ssl_context = ServerSSLContextFactory(
                key_path=self.key_path,
                certificate_path=self.certificate_path,
                ca_path=self.ca_path,
                crl_path=self.crl_path,
                allowed_methods=self.allowed_methods,
                cipher_list=self.cipher_list,
                )
        except SSL.Error, ssl_error:
            log(10015, _(
                u'Failed to initialize the SSL/TLS context. '
                u'Using cert:%s and key:%s. '
                u'SSL error: %s.' % (
                    self.certificate_path, self.key_path, unicode(ssl_error))))
            raise AssertionError

    def reconfigureSSL(self):
        '''Reconfigure the SSL.'''
        self.ssl_context = None
        self.configureSSL()
        time.sleep(0.0001)
