# Copyright (c) 2010 Adi Roiban.
# See LICENSE for details.
'''Chevah FTP factory module.'''

from __future__ import with_statement

from twisted.protocols import policies

from chevah.txftps.protocol import (
    FTPInternalErrorProtocol,
    FTPProtocol,
    FTPSIProtocol,
    FTPOverflowProtocol,
    )


class FTPFactory(policies.LimitTotalConnectionsFactory):
    '''Factory for creating FTP protocol instances.'''

    # Number of seconds after an inactive command channel is closed.
    idle_connection_timeout = 120

    # Number of seconds after an inactive data channel is closed.
    dtp_timeout = 10

    # Total number of command channel session allowed to be active
    # in the same time.
    connectionLimit = 10

    # Range in which passive ports are opened.
    passive_port_range = xrange(9000, 10000)

    # If SSL (FTPES/FTPIS) support is enabled.
    ssl_enabled = True

    # Username and password can only be send over a secured channel.
    ftps_force_secured_authentication = True

    # Command channel should always be kept secured.
    # CCC command not allowed.
    ftps_force_secured_command_channel = True

    # Data channel should always be kept secured.
    ftps_force_secured_data_channel = True

    # Users can be authenticated based on username and password.
    enable_password_authentication = True

    # Users can be autenticated based on username and SSL Common Name.
    enable_ssl_certificate_authentication = True

    # Message show to new connections.
    welcome_message = "Welcome to Chevah FTP/FTPS Server."

    # FTP variables.
    protocol = FTPProtocol
    allowAnonymous = False
    userAnonymous = 'anonymous'

    # LimitTotalConnectionsFactory variables.
    connectionCount = 0
    overflowProtocol = FTPOverflowProtocol

    def __init__(self):
        self.instances = []

    def buildProtocol(self, addr):
        """
        Create a new instance of protocol for peer.

        When we failed to initialize the protocol,
        return FTPInternalErrorProtocol to handle failed initializations.
        """
        try:
            new_protocol = (
                policies.LimitTotalConnectionsFactory.buildProtocol(
                    self, addr))

            if new_protocol is None:
                return None

            wrapped_protocol = new_protocol.wrappedProtocol
            wrapped_protocol.portal = self.portal
            wrapped_protocol.timeOut = self.idle_connection_timeout
            wrapped_protocol.passive_port_range = self.passive_port_range

        except:
            import traceback
            details = traceback.format_exc()
            new_protocol = FTPInternalErrorProtocol()
            new_protocol.details = details

        return new_protocol

    def stopFactory(self):
        # make sure ftp instance's timeouts are set to None
        # to avoid reactor complaints
        [p.setTimeout(None) for p in self.instances if p.timeOut is not None]
        policies.LimitTotalConnectionsFactory.stopFactory(self)

    @property
    def timeOut(self):
        """
        Alias for idle_connection_timeout.

        The ftp.Protocol should use self.timeOut rather than
        self.factory.timeOUt.
        """
        return self.idle_connection_timeout


class FTPSIFactory(FTPFactory):
    """
    Factory for FTPS Implicit.
    """

    protocol = FTPSIProtocol

    @property
    def ssl_enabled(self):
        """
        SSL is always enabled.
        """
        return True

    @property
    def ftps_force_secured_authentication(self):
        return True

    @property
    def ftps_force_secured_command_channel(self):
        return True

    @property
    def ftps_force_secured_data_channel(self):
        return True
