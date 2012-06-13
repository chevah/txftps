'''Twisted FTP Protocol extension for expkicit FTPS.

Since ASCII is a subset of UTF-8, UTF-8 support is enabled by default.
Main RFCs:
 * http://tools.ietf.org/html/rfc959
 * http://tools.ietf.org/html/rfc3659
 * http://tools.ietf.org/html/rfc4217
'''

from __future__ import with_statement
from OpenSSL import SSL

from twisted.cred.credentials import UsernamePassword
from twisted.internet import error, reactor, defer
from twisted.protocols import ftp
from twisted.protocols.ftp import (
    AuthorizationError,
    decodeHostPort,
    FTP,
    RESPONSE,
    )

from txftps.logger import _, log
from txftps.credentials import UsernameSSLCertificate
from txftps.ssl import NiceTLSMemoryBIOFactory


PBSZ_OK = '200.100'
PROT_OK_CLEAR = '200.101'
PROT_OK_PRIVATE = '200.102'
OPTS_UTF8_OK = '200.103'
ALREADY_AUTH = '200.104'
FEAT_OK = '211.100'
USR_LOGGED_IN_SSL_PROCEED = '232.100'
AUTH_OK = '234.100'

AUTH_BAD = '502.100'
PROT_UNRECOGNIZED = '502.101'
OPTS_NOT_IMPLEMENTED = '502.102'
AUTH_ALREADY = '503.100'
PBSZ_BAD = '503.101'
PROT_NOT_ALLOWED = '503.102'
PROT_DO_PBSZ_FIRST = '503.103'
PROT_UNSUPORTED = '521.100'
SSL_COMMAND_REQUIRED = '550.100'
SSL_DATA_REQUIRED = '550.101'
SSL_CERT_REQUIRED = '550.102'
NO_AUTH_METHOD_ENABLED = '550.104'

RESPONSE[PBSZ_OK] = '200 PBSZ=0 successful.'
RESPONSE[PROT_OK_CLEAR] = '200 Protection set to Clear.'
RESPONSE[PROT_OK_PRIVATE] = '200 Protection set to Private.'
RESPONSE[OPTS_UTF8_OK] = '200 Always in UTF8 mode.'
RESPONSE[ALREADY_AUTH] = '200 User is already authenticated.'
RESPONSE[USR_LOGGED_IN_SSL_PROCEED] = (
    '232 User logged in, authorized by security data exchange')
RESPONSE[AUTH_OK] = '234 Security data exchange complete.'
RESPONSE[FEAT_OK] = '211-Features:%s211 End'

RESPONSE[AUTH_BAD] = '502 Unrecognized encryption type (use TLS or SSL).'
RESPONSE[PROT_UNRECOGNIZED] = '502 Unrecognized PROT type (use C or P).'
RESPONSE[OPTS_NOT_IMPLEMENTED] = '502 Command not implemented.'
RESPONSE[AUTH_ALREADY] = '503 Already using TLS.'
RESPONSE[PBSZ_BAD] = '503 PBSZ not allowed on insecure control connection.'
RESPONSE[PROT_NOT_ALLOWED] = (
    '503 PROT not allowed on insecure control connection.')
RESPONSE[PROT_DO_PBSZ_FIRST] = (
    '503 You must issue the PBSZ command prior to PROT.')
RESPONSE[PROT_UNSUPORTED] = '521 PROT %s unsupported (use C or P).'
RESPONSE[SSL_COMMAND_REQUIRED] = (
    '550 SSL/TLS required on the control channel.')
RESPONSE[SSL_DATA_REQUIRED] = (
    '550 SSL/TLS required on the data channel.')
RESPONSE[SSL_CERT_REQUIRED] = (
    '550 Users are required to authenticate using a SSL certificates.')
RESPONSE[NO_AUTH_METHOD_ENABLED] = (
    '550 No authentication method enabled on the server.')


class FTPProtocol(FTP):
    '''Extending twisted.protocols.ftp to implement explicit FTPS.'''

    dtpTimeout = 30
    PUBLIC_COMMANDS = ['QUIT', 'FEAT']

    def __init__(self):
        # For now we need to deal with twisted naming convention.
        # pylint: disable=C0103
        # Portal and Factory are set by the FTPFactory.
        self.factory = None
        self.portal = None
        self.workingDirectory = []
        self.shell = None
        self.state = self.UNAUTH
        self.logout = None
        self._pbsz = False
        self._protected_data_requested = False
        self._protected_command_requested = False
        self._auth_just_called = False
        self._avatar = None
        self._debug = False

    def rawDataReceived(self, data):
        '''FTP protocol should not use raw data.'''
        raise AssertionError('FTP protocol should not receive raw data.')

    def _resetSSLStatus(self):
        '''Reset SSL/TLS related status.'''
        self._pbsz = False
        self._protected_data_requested = False
        self._protected_command_requested = False

    @property
    def is_ftps_command_active(self):
        '''Return `True` if current command connection is using SSL.'''
        return self._protected_command_requested

    @property
    def _peer(self):
        '''Return the remote peer.'''
        return self.transport.getPeer()

    def connectionMade(self):
        '''Called when a new command connection was made.'''
        self._resetSSLStatus()
        super(FTPProtocol, self).connectionMade()

    def connectionLost(self, reason):
        '''Callend when the current command connection was lost.'''
        if self._auth_just_called:
            log(10014,
                _(u'Clients are required to send a valid certificate. '
                  u'Maybe the client did not sent a certificate or '
                  u'the client certificate is not valid.'),
                avatar=self._avatar, peer=self._peer)

        log(10034,
            _(u'Client FTP/FTPS connection lost.'),
            avatar=self._avatar, peer=self._peer)
        self._avatar = None
        super(FTPProtocol, self).connectionLost(reason)

    def timeoutConnection(self):
        log(10084,
            _(u'Client FTP/FTPS connection timed out.'),
            avatar=self._avatar, peer=self._peer)
        self._avatar = None
        super(FTPProtocol, self).timeoutConnection()

    def processCommand(self, cmd, *params):
        '''Process FTP commands.

        If FTPS is enabled and secure connections are forced, make sure
        we have a secure channel before executing commands.
        '''
        cmd = cmd.upper()
        if self._debug:
            log(10011,
                _(u'Received command "%s" with "%s".' % (cmd, params)),
                avatar=self._avatar, peer=self._peer)

        # This is a flag to detect connection errors due to clients
        # that are not sending a certificate.
        self._auth_just_called = False

        if cmd in self.PUBLIC_COMMANDS:
            method = getattr(self, "ftp_" + cmd, None)
            if method is not None:
                return method(*params)

        if self.factory.ssl_enabled:
            if cmd in ('USER', 'PASS'):
                if (self.factory.ssl_command_required and
                        not self.is_ftps_command_active):
                    log(10035,
                        _(u'SSL/TLS required on the command channel.'),
                        avatar=self._avatar, peer=self._peer)
                    return SSL_COMMAND_REQUIRED
            elif cmd in ('PASV', 'EPSV', 'PORT', 'EPRT'):
                if (self.factory.ssl_data_required and
                    not self._protected_data_requested):
                    log(10036,
                        _(u'SSL/TLS required on the data channel.'),
                        avatar=self._avatar, peer=self._peer)
                    return SSL_DATA_REQUIRED
            elif cmd == 'AUTH':
                return self.ftp_AUTH(*params)
            elif cmd == 'PBSZ':
                return self.ftp_PBSZ(*params)
        # Call parent is we are not handling the command.

        if self.state == self.AUTHED and cmd == 'RNTO':
            return ftp.BAD_CMD_SEQ, 'RNFR required before RNTO.'

        return super(
            FTPProtocol, self).processCommand(cmd, *params)

    def ftp_FEAT(self):
        '''Advertise the features supported by the server.

        http://tools.ietf.org/html/rfc2389
        '''
        features = (
            '\n'
            ' AUTH SSL\n'
            ' AUTH TLS\n'
            ' MDTM\n'
            ' PASV\n'
            ' PBSZ\n'
            ' PROT\n'
            ' SIZE\n'
            ' TYPE A;I;U\n'
            ' UTF8\n'
            '')
        return self.reply(FEAT_OK, features)

    def ftp_AUTH(self, mode):
        '''Set up secure control channel.

        http://tools.ietf.org/html/rfc4217
        '''
        arg = mode.upper()
        if self.is_ftps_command_active:
            return AUTH_ALREADY
        if arg in ('TLS', 'TLS-C', 'SSL', 'TLS-P'):
            # From RFC-4217: "As the SSL/TLS protocols self-negotiate
            # their levels, there is no need to distinguish between SSL
            # and TLS in the application layer".
            self.reply(AUTH_OK)
            self.transport.startTLS(self.factory.ssl_context, self.factory)
            self._protected_command_requested = True
            self._auth_just_called = True
            log(10024,
                _(u'Secure command channel successfully initialized.'),
                peer=self._peer)
            return None
        else:
            self._protected_command_requested = False
            return AUTH_BAD

    def ftp_OPTS(self, option):
        '''Handle OPTS command.

        http://tools.ietf.org/html/draft-ietf-ftpext-utf-8-option-00
        '''
        if option.lower().startswith('utf8'):
            # Filezilla uses OPTS UTF8 ON ... but by RFC it should be only
            # OPTS UTF8 ... so just look for starting.
            return self.reply(OPTS_UTF8_OK)
        return self.reply(OPTS_NOT_IMPLEMENTED)

    def ftp_PBSZ(self, line):
        '''Negotiate size of buffer for secure data transfer.

        For TLS/SSL the only valid value for the parameter is '0'.
        Any other value is accepted but ignored.

        http://tools.ietf.org/html/rfc4217
        '''
        # Ignore `line` since it is an API requirement.
        # pylint: disable=W0613
        if not self.is_ftps_command_active:
            return PBSZ_BAD
        else:
            self._pbsz = True
            return PBSZ_OK

    def ftp_PORT(self, address):
        '''DATA PORT (PORT)

        The argument is a HOST-PORT specification for the data port
        to be used in data connection.  There are defaults for both
        the user and server data ports, and under normal
        circumstances this command and its reply are not needed.  If
        this command is used, the argument is the concatenation of a
        32-bit internet host address and a 16-bit TCP port address.
        This address information is broken into 8-bit fields and the
        value of each field is transmitted as a decimal number (in
        character string representation).  The fields are separated
        by commas.  A port command would be:
           PORT h1,h2,h3,h4,p1,p2
        where h1 is the high order 8 bits of the internet host
        address.
        '''

        addr = map(int, address.split(','))
        ip = '%d.%d.%d.%d' % tuple(addr[:4])
        port = addr[4] << 8 | addr[5]
        ip, port = decodeHostPort(address)

        log(10062,
            _(u'Active transfer requested to "%s:%d".' % (ip, port)),
            self._avatar,
            )
        # if we have a DTP port set up, lose it.
        if self.dtpFactory is not None:
            self.cleanupDTP()

        self.dtpFactory = ftp.DTPFactory(
            pi=self, peerHost=self.transport.getPeer().host)
        self.dtpFactory.setTimeout(self.dtpTimeout)

        if self._protected_data_requested:
            # It is strange, but for acctive connection the SSL
            # layer is still seen as a server.
            tls_factory = NiceTLSMemoryBIOFactory(
                contextFactory=self.factory.ssl_context,
                isClient=False,
                wrappedFactory=self.dtpFactory,
                )
            self.dtpPort = reactor.connectTCP(ip, port, tls_factory)
        else:
            self.dtpPort = reactor.connectTCP(ip, port, self.dtpFactory)

        def connected(ignored):
            log(10063,
                _(u'Successfully initiated active connection.'), self._avatar)
            return ftp.ENTERING_PORT_MODE

        def connFailed(err):
            log(10064,
                _(u'Failed to initiate active connection.'), self._avatar)
            err.trap(ftp.PortConnectionError)
            return ftp.CANT_OPEN_DATA_CNX

        return self.dtpFactory.deferred.addCallbacks(connected, connFailed)

    def ftp_PROT(self, line):
        '''Data Connection Security Negotiation the

          The command defined in [RFC-2228] to negotiate data connection
          security is the PROT command.  As defined, there are four values
          that the PROT command parameter can take.
                'C' - Clear - neither Integrity nor Privacy
                'S' - Safe - Integrity without Privacy
                'E' - Confidential - Privacy without Integrity
                'P' - Private - Integrity and Privacy

          As TLS negotiation encompasses (and exceeds) the Safe /
          Confidential / Private distinction, only Private (use TLS) and
          Clear (don't use TLS) are used.

          For TLS, the data connection can have one of two security levels.
                1) Clear (requested by 'PROT C')
                2) Private (requested by 'PROT P')

        http://tools.ietf.org/html/rfc4217
        '''
        arg = line.upper()
        if not self.is_ftps_command_active:
            return PROT_NOT_ALLOWED
        elif not self._pbsz:
            return PROT_DO_PBSZ_FIRST
        elif arg == 'C':
            self._protected_data_requested = False
            return PROT_OK_CLEAR
        elif arg == 'P':
            self._protected_data_requested = True
            return PROT_OK_PRIVATE
        elif arg in ('S', 'E'):
            return PROT_UNSUPORTED, arg
        else:
            return PROT_UNRECOGNIZED

    def ftp_QUIT(self):
        '''LOGOUT (QUIT)

        This command terminates a USER and if file transfer is not
        in progress, the server closes the control connection.  If
        file transfer is in progress, the connection will remain
        open for result response and the server will then close it.
        If the user-process is transferring files for several USERs
        but does not wish to close and then reopen connections for
        each, then the REIN command should be used instead of QUIT.

        An unexpected close on the control connection will cause the
        server to take the effective action of an abort (ABOR) and a
        logout (QUIT).
        '''
        log(10066,
                _(u'Closing current session.'), self._avatar)
        self._resetSSLStatus()
        self.reply(ftp.GOODBYE_MSG)
        self.transport.loseConnection()
        self.disconnected = True


    def ftp_USER(self, username):
        '''USER NAME (USER)

        The argument field is a Telnet string identifying the user.
        The user identification is that which is required by the
        server for access to its file system.  This command will
        normally be the first command transmitted by the user after
        the control connections are made (some servers may require
        this).  Additional identification information in the form of
        a password and/or an account command may also be required by
        some servers.  Servers may allow a new USER command to be
        entered at any point in order to change the access control
        and/or accounting information.  This has the effect of
        flushing any user, password, and account information already
        supplied and beginning the login sequence again.  All
        transfer parameters are unchanged and any file transfer in
        progress is completed under the old access control
        parameters.

        If password based authentication is enabled, the peer SSL certificate
        validation will be optional.
        '''
        if not username:
            return defer.fail(ftp.CmdSyntaxError('USER requires an argument'))

        username_utf8 = username.decode('utf-8')
        log(10067,
            _(u'Client initiating authentication as "%s".' % (
                username_utf8)), peer=self._peer)

        def proceed_with_password_authentication():
            '''Prepare the session for next PASS command.'''
            self._user = username
            self.state = self.INAUTH
            return (ftp.USR_NAME_OK_NEED_PASS, username)

        def proceed_with_ssl_certificate_authentication(peer_certificate):
            '''Attempt to authenticate based on SSl certificate.'''
            self._user = username
            self.state = self.INAUTH

            def cb_ssl_certificate_error(failure):
                '''Log password error and call general login error.'''
                if self.factory.enable_password_authentication:
                    return proceed_with_password_authentication()
                else:
                    log(10029,
                        _(u'Failed to validate SSL certificate for '
                          u'user "%s".' % (
                            self._user.decode('utf-8'))),
                        peer=self._peer)
                    return self._cbAuthenticationError(failure)

            def cb_ssl_authentication_done(result):
                '''Callback for handling finalized SSL login.'''
                (interface, avatar, logout) = result
                self._setupSession(avatar, logout)
                # Delete temporary _user variable used between USER and PASS
                # commands.
                del self._user
                return USR_LOGGED_IN_SSL_PROCEED

            credentials = UsernameSSLCertificate(
                username=username_utf8, certificate=peer_certificate)
            defered_login = self.portal.login(credentials, None)
            defered_login.addCallbacks(
                cb_ssl_authentication_done, cb_ssl_certificate_error)
            return defered_login

        def inform_ssl_authentication_required():
            '''On SSL auth failure, try password authentication if enabled or
            inform client that SSL authentication is required.'''
            log(10028,
                _(u'Users are required to authenticate using '
                    u'a SSL certificate.'),
                peer=self._peer)
            return SSL_CERT_REQUIRED

        if self.factory.enable_ssl_certificate_authentication:
            peer_certificate = self._getPeerCertificate()
            if peer_certificate is None:
                if self.factory.enable_password_authentication:
                    return proceed_with_password_authentication()
                else:
                    return inform_ssl_authentication_required()
            else:
                return proceed_with_ssl_certificate_authentication(
                    peer_certificate)
        elif self.factory.enable_password_authentication:
                return proceed_with_password_authentication()
        else:
            self.state = self.UNAUTH
            log(10027,
                _(u'No authentication method was enabled for this service.'),
                peer=self._peer)
            return NO_AUTH_METHOD_ENABLED

    def _getPeerCertificate(self):
        '''Return the peer certificate if remote peer is on a SSL connection
        and has sent us a certificate.
        Return `None` otherwise.
        '''
        if not hasattr(self.transport, 'socket'):
            return None
        if not self.is_ftps_command_active:
            return None
        return self.transport.getPeerCertificate()

    def ftp_PASS(self, password):
        """
        Second part of login. Get the password the peer wants to
        authenticate with.
        """
        if self.state == self.AUTHED:
            return ALREADY_AUTH
        username = self._user.decode('utf-8')
        password = password.decode('utf-8')
        log(10058,
            _(u'Validating password for user "%s".' % (username)),
            peer=self._peer)

        def cb_password_error(failure):
            '''Log password error and call general login error.'''
            log(10060,
                _(u'Failed to validate password for user "%s".' % (
                    self._user.decode('utf-8'))),
                peer=self._peer)
            return self._cbAuthenticationError(failure)

        def cb_password_authentication_done(result):
            '''Callback for handling finalized login.'''
            (interface, avatar, logout) = result
            self._setupSession(avatar, logout)
            # Delete temporary _user variable used between USER and PASS
            # commands.
            del self._user
            return ftp.USR_LOGGED_IN_PROCEED

        credentials = UsernamePassword(self._user, password)
        defered_login = self.portal.login(credentials, None, ftp.IFTPShell)
        defered_login.addCallbacks(
            cb_password_authentication_done, cb_password_error)
        return defered_login

    def _cbAuthenticationError(self, failure):
        '''Callback for handling errors in login.'''
        self.state = self.UNAUTH
        del self._user
        raise AuthorizationError()

    def _setupSession(self, avatar, logout):
        '''Prepare the FTP session after successful login.'''
        self.shell = avatar
        self._avatar = avatar

        self.logout = logout
        self.workingDirectory = []
        self.state = self.AUTHED
        log(10059,
            _(u'User "%s" successfully loged.' % (self._user)),
            self._avatar,
            )

    def getDTPPort(self, factory):
        """
        Return a port for passive access, using C{self.passivePortRange}
        attribute.
        """
        for portn in self.passivePortRange:
            try:
                if self._protected_data_requested:
                    tls_factory = NiceTLSMemoryBIOFactory(
                        contextFactory=self.factory.ssl_context,
                        isClient=False,
                        wrappedFactory=factory)
                    dtpPort = reactor.listenTCP(
                        port=portn, factory=tls_factory)
                else:
                    dtpPort = self.listenFactory(portn, factory)

            except error.CannotListenError:
                continue
            else:
                log(10083,
                    _(u'Listening on port %d for the next passive '
                      u'request.' % (dtpPort.getHost().port)), self._avatar)
                return dtpPort
        raise error.CannotListenError(
            '', portn, u'No port available in range %s' % (
                unicode(self.passivePortRange)))
