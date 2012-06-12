# Copyright (c) 2010 Adi Roiban.
# See LICENSE for details.
'''Server SSL context factory.'''

from __future__ import with_statement
from hashlib import md5
from OpenSSL import SSL, crypto
from time import time
import itertools
import os

from twisted.internet import reactor, defer
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.protocols.ftp import (
    AuthorizationError,
    )
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.python import reflect


from txftps.logger import _, log

from txftps.constants import (
    DEFAULT_ALLOWED_METHODS,
    DEFAULT_CIPHER_LIST,
    SSL_CONNECTION_CLOSE_TIMEOUT,
    )

_sessionCounter = itertools.count().next


class ServerSSLContextFactory(DefaultOpenSSLContextFactory):
    '''OpenSSL context factory with support for CA and CRL checks.

    The context is cached and used as a singleton.
    '''

    def __init__(self,
                key_path,
                certificate_path,
                ca_path=None,
                crl_path=None,
                cipher_list=None,
                allowed_methods=None,
                enable_session_tickets=True,
                ):
        self.key_path = key_path
        self.certificate_path = certificate_path
        self.ca_path = ca_path
        self.crl_path = crl_path

        if cipher_list is None:
            cipher_list = DEFAULT_CIPHER_LIST
        self.cipher_list = cipher_list

        if allowed_methods is None:
            allowed_methods = DEFAULT_ALLOWED_METHODS
        self.allowed_methods = allowed_methods

        self.enable_session_tickets = enable_session_tickets
        self._revocation_list = []
        self._makeContext()

    def _getCertificateSubject(self, certificate):
        '''Return human readable subject line.'''
        return unicode(certificate.get_subject().get_components())

    def _cbVerifyClientCertificate(self,
        connection, certificate, errnum, errdepth, code):

        def get_peer(connection):
            '''Return human readable peer id.'''
            peer = connection.getpeername()
            return peer

        if not code:
            if certificate.has_expired():
                log(10023,
                    _(u'Client certificate has expired. '
                     u'Certificate subject: "%s". '
                     u'Client address: %s.' % (
                        self._getCertificateSubject(certificate),
                        get_peer(connection),
                        )))
            return False
        else:
            if certificate.get_serial_number() in self._revocation_list:
                log(10022,
                    _(u'Client certificate was revoked. '
                      u'Certificate subject: "%s". '
                      u'Client address: %s.' % (
                        self._getCertificateSubject(certificate),
                        get_peer(connection),
                        )))
                return False
            else:
                return True

    def _makeContext(self):
        # We start by allowing all SSL/TLS methods, including SSLv2 and then
        # disable them using SSL_OP_NO_*
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.use_certificate_file(self.certificate_path)
        context.use_privatekey_file(self.key_path)
        if self.ca_path:
            context.set_verify(
                SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT |
                SSL.VERIFY_CLIENT_ONCE,
                self._cbVerifyClientCertificate)
            if os.path.isdir(self.ca_path):
                context.load_verify_locations(None, self.ca_path)
            else:
                context.load_verify_locations(self.ca_path, None)

            if self.crl_path:
                if os.path.isdir(self.crl_path):
                    log(10012, _(
                        u'Certificate revocation list can only be used '
                        u'together with a single certificate authority.')
                        )
                    raise AssertionError
                # Load certificate revocation list
                # A list containing IDs for revoked certificates.
                crl_data = None
                try:
                    crl_file = open(self.crl_path, 'rb')
                    try:
                        crl_data = crl_file.read()
                    finally:
                        crl_file.close()

                    if crl_data:
                        crl = crypto.load_crl(crypto.FILETYPE_PEM, crl_data)
                        self._revocation_list = []
                        revoked_certificates = crl.get_revoked()
                        if revoked_certificates is not None:
                            for revoked in revoked_certificates:
                                self._revocation_list.append(
                                    long(revoked.get_serial()))
                except (IOError, OSError), io_error:
                    log(10013, _(
                        u'Could not read the certificate revocation list '
                        u'file located at %s. Error: %s' % (
                            self.crl_path, unicode(io_error))))
                    raise AssertionError

        # Older versions of PyOpenSSL didn't provide OP_ALL.
        # Fudge it here, just in case.
        # SSL.OP_ALL is used to enable workaround for various SSL
        # implementation
        # See: http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
        self._OP_ALL = getattr(SSL, 'OP_ALL', 0x0000FFFF)
        context.set_options(self._OP_ALL)

        if self.enable_session_tickets:
            # OP_NO_TICKET is not (yet) exposed by PyOpenSSL
            self._OP_NO_TICKET = 0x00004000
            context.set_options(self._OP_NO_TICKET)

        context.set_options(SSL.OP_SINGLE_DH_USE)

        context.set_cipher_list(self.cipher_list)

        blocked_methods = self.convertAllowdMethodsToBlockedSSLOptionsList(
            self.allowed_methods)

        for no_method in blocked_methods:
            context.set_options(no_method)

        sessionName = md5("%s-%d" % (
            reflect.qual(self.__class__), _sessionCounter())).hexdigest()
        context.set_session_id(sessionName)

        def info_callback(conn, where, ret):
            # conn is a OpenSSL.SSL.Connection
            # where is a set of flags telling where in the handshake we are
            # http://www.openssl.org/docs/ssl/SSL_CTX_set_info_callback.html
            if where & SSL.SSL_CB_HANDSHAKE_START:
                conn.set_app_data({'handshake_done': False})
            if where & SSL.SSL_CB_HANDSHAKE_DONE:
                conn.set_app_data({'handshake_done': True})

        context.set_info_callback(info_callback)

        self._context = context

    def convertAllowdMethodsToBlockedSSLOptionsList(self,
        allowed_methods=None):
        '''Convert the string of allowed methods to a list of SSL options
        to be applied on the SSL_CONTEXT as OP_NO_METHOD.

        This is a bit strange, since we configure the list of allowed methods,
        while OpenSSL is configured by listing the blocked SSL methods.

        It will start with a list that will block all methods and then
        remove from the list the allowed methods.
        '''
        ssl_options = [SSL.OP_NO_SSLv2, SSL.OP_NO_SSLv3, SSL.OP_NO_TLSv1]

        if allowed_methods is None or allowed_methods == '':
            return ssl_options

        for method in allowed_methods.split(' '):
            if method == '':
                '''Skip emtpy methods.'''
                continue

            if method.lower() == 'sslv3':
                ssl_options.remove(SSL.OP_NO_SSLv3)
            elif method.lower() == 'tlsv1':
                ssl_options.remove(SSL.OP_NO_TLSv1)
            else:
                log(10031, _(
                    u'Unknown SSL/TLS method "%s".' % (method)))
                raise AuthorizationError
        return ssl_options


class NiceTLSMemoryBIOProtocol(TLSMemoryBIOProtocol, object):
    '''TLSMemoryBIOProtocol with support for closing the connection in a
    clean state.

    It will wait for the initial SSL handshake to finish, before closing
    the connection.
    '''

    def _cbCloseConnection(self, result):
        '''Disconnect the transport.'''
        self.disconnecting = True
        if not self._writeBlockedOnRead:
            self._tlsConnection.shutdown()
            self._flushSendBIO()
            self.transport.loseConnection()

    def _checkHandshakeDone(self, deferred):
        '''Check that handshake is done and trigger the deferred.'''
        ssl_all_data = self._tlsConnection.get_app_data()
        if ssl_all_data and 'handshake_done' in ssl_all_data:
            if ssl_all_data['handshake_done'] is True:
                deferred.callback(None)
            else:
                reactor.callLater(0.5, self._checkHandshakeDone, deferred)
        else:
            close_duration = time() - self.lose_connection_start_time
            if (close_duration > SSL_CONNECTION_CLOSE_TIMEOUT):
                log(10021,
                    u'Connection was closed before finalization '
                    u'of the SSL handshake.',
                    peer=self.getPeer(),
                    )
                deferred.callback(None)
            else:
                reactor.callLater(0.5, self._checkHandshakeDone, deferred)

    def loseConnection(self):
        """
        Monkey patching for TLSMemoryBIOProtocol to wait for handshake to end,
        before closing the connection.

        Send a TLS close alert and close the underlying connection.
        """
        self.lose_connection_start_time = time()
        deferred = defer.Deferred()
        deferred.addCallback(self._cbCloseConnection)
        reactor.callLater(0, self._checkHandshakeDone, deferred)
        return deferred


class NiceTLSMemoryBIOFactory(TLSMemoryBIOFactory, object):
    '''Adapter for NiceTLSMemoryProtocol to TLSMemoryBIOFactory.'''

    protocol = NiceTLSMemoryBIOProtocol
