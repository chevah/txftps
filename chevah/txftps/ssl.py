# Copyright (c) 2010 Adi Roiban.
# See LICENSE for details.
'''SSL commons support for services.'''
from __future__ import with_statement
from OpenSSL import SSL
from time import time
import itertools

from twisted.internet import defer, reactor
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol

from chevah.txftps.logger import log
from chevah.txftps.constants import (
    DEFAULT_ALLOWED_METHODS,
    DEFAULT_CIPHER_LIST,
    SSL_CONNECTION_CLOSE_TIMEOUT,
    )

_sessionCounter = itertools.count().next

SSL_DEFAULTS = {
    'service_ssl_certificate': u'no-certificate-defined',
    'service_ssl_key': 'None',
    'service_ssl_key_password': 'None',
    'service_ssl_certificate_authority': 'None',
    'service_ssl_certificate_revocation_list': 'None',
    'service_ssl_cipher_list': DEFAULT_CIPHER_LIST,
    'service_ssl_allowed_methods': DEFAULT_ALLOWED_METHODS,
    }


def patch_loseConnection(self):
    """
    Send a TLS close alert and close the underlying connection.

    This patches the TLSMemoryBIOProtocol to set
    SSL.SENT_SHUTDOWN | SSL.RECEIVED_SHUTDOWN
    before sending shutdown.
    """
    if self.disconnecting:
        return
    self.disconnecting = True
    if not self._writeBlockedOnRead and self._producer is None:
        self._tlsConnection.set_shutdown(
            SSL.SENT_SHUTDOWN | SSL.RECEIVED_SHUTDOWN)
        self._shutdownTLS()
TLSMemoryBIOProtocol.loseConnection = patch_loseConnection


class ChevahTLSMemoryBIOProtocol(TLSMemoryBIOProtocol, object):
    '''TLSMemoryBIOProtocol used by Chevah services.

    This is a patched TLSMemoryBIOProtocol with support for closing the
    connection is an _nice_ way.
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


class ChevahTLSMemoryBIOFactory(TLSMemoryBIOFactory, object):
    '''Adapter for ChevahTLSMemoryProtocol to TLSMemoryBIOFactory.'''

    protocol = ChevahTLSMemoryBIOProtocol
