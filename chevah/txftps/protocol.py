# Copyright (c) 2010-2013 Adi Roiban.
# See LICENSE for details.
"""
Chevah FTP Protocol.

One instance of FTP protocl is created by the FTP Factory for each client
session.

Since ASCII is a subset of UTF-8, UTF-8 support is enabled by default.
Main RFCs:
 * http://tools.ietf.org/html/rfc959
 * http://tools.ietf.org/html/rfc3659
 * http://tools.ietf.org/html/rfc4217
"""

from __future__ import with_statement

from OpenSSL import SSL
from twisted.internet import error, reactor, defer
from twisted.python.failure import Failure
from twisted.protocols import ftp, policies
from twisted.protocols.basic import LineReceiver
from twisted.protocols.ftp import (
    AuthorizationError,
    decodeHostPort,
    FTP,
    RESPONSE,
    FTPShell,
    IFTPShell,
    )

from chevah.txftps.credentials import (
    FTPPasswordCredentials,
    FTPSPasswordCredentials,
    FTPSSSLCertificateCredentials,
    )
from chevah.txftps.logger import _, emit, log
from chevah.txftps.ssl import ChevahTLSMemoryBIOFactory

# constants
# response codes
PBSZ_OK = '200.100'
PROT_OK_CLEAR = '200.101'
PROT_OK_PRIVATE = '200.102'
OPTS_UTF8_OK = '200.103'
ALREADY_AUTH = '200.104'
EPSV_ALL_OK = '200.105'
ENTERING_EPRT_MODE = '200.106'
CCC_OK = '200.107'
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
EPSV_ALL_ACTIVE = '503.104'
PROT_UNSUPORTED = '521.100'
EPSV_UNKNOWN_PROTOCOL = '522.100'
CCC_ALREADY = '533.100'
CCC_NOT_ALLOWED = '534.100'
SSL_COMMAND_REQUIRED = '550.100'
SSL_DATA_REQUIRED = '550.101'
SSL_CERT_REQUIRED = '550.102'
NO_AUTH_METHOD_ENABLED = '550.104'

RESPONSE[PBSZ_OK] = '200 PBSZ=0 successful.'
RESPONSE[PROT_OK_CLEAR] = '200 Protection set to Clear.'
RESPONSE[PROT_OK_PRIVATE] = '200 Protection set to Private.'
RESPONSE[OPTS_UTF8_OK] = '200 Always in UTF8 mode.'
RESPONSE[ALREADY_AUTH] = '200 User is already authenticated.'
RESPONSE[EPSV_ALL_OK] = '200 EPSV ALL OK.'
RESPONSE[ENTERING_EPRT_MODE] = '200 EPRT OK.'
RESPONSE[CCC_OK] = '200 Clear Command Channel OK.'
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
RESPONSE[EPSV_ALL_ACTIVE] = '503 EPSV ALL was enabled.'
RESPONSE[PROT_UNSUPORTED] = '521 PROT %s unsupported (use C or P).'
RESPONSE[EPSV_UNKNOWN_PROTOCOL] = (
    '522 Network protocol not supported, use (%s).')
RESPONSE[CCC_ALREADY] = '533 Command channel is alredy cleared.'
RESPONSE[CCC_NOT_ALLOWED] = '534 Clear Command Channel not allowed.'
RESPONSE[SSL_COMMAND_REQUIRED] = (
    '550 SSL/TLS required on the control channel.')
RESPONSE[SSL_DATA_REQUIRED] = (
    '550 SSL/TLS required on the data channel.')
RESPONSE[SSL_CERT_REQUIRED] = (
    '550 Users are required to authenticate using a SSL certificates.')
RESPONSE[NO_AUTH_METHOD_ENABLED] = (
    '550 No authentication method enabled on the server.')


def to_segments(cwd, path):
    '''
    Normalize a path, as represented by a list of strings each
    representing one segment of the path.

    This is the place where segments are created and we make sure
    they are unicode.
    '''
    if path.startswith('/'):
        segs = []
    else:
        segs = cwd[:]

    for s in path.split('/'):
        if s == '.' or s == '':
            continue
        elif s == '..':
            if segs:
                segs.pop()
            else:
                raise ftp.InvalidPath(cwd, path)
        elif '\0' in s or '/' in s:
            raise ftp.InvalidPath(cwd, path)
        else:
            segs.append(s.decode('utf-8'))
    return segs


ftp.toSegments = to_segments


class FTPAvatar(object):
    """
    Simple object for keeping track of FTP account.
    """

    def __init__(self, name, peer):
        self.name = name
        self.peer = peer


class FTPProtocol(FTP):
    '''Extending twisted.protocols.ftp to implement explicit FTPS.

    It also fixed a few bugs for Chevah.
    '''

    PUBLIC_COMMANDS = ['QUIT', 'FEAT']

    def __init__(self):
        self.factory = None
        self.workingDirectory = []
        self.shell = None
        self.state = self.UNAUTH
        self.logout = None
        self._pbsz = False
        self._protected_data_requested = False
        self._protected_command_requested = False
        self._avatar = None
        self._debug = False
        self._disable_new_connections = False

    @property
    def is_ftps_command_active(self):
        '''Return `True` if current command connection is using SSL.'''
        return self._protected_command_requested

    @property
    def have_valid_authentication_channel(self):
        """
        Return True if command channel is prepared for sending
        authentication requests.
        """
        ssl_required = (
            self.factory.ftps_force_secured_command_channel or
            self.factory.ftps_force_secured_authentication)
        if not ssl_required:
            return True

        return self.is_ftps_command_active

    @property
    def dtpTimeout(self):
        """
        Raise a warning when dtpTimeout is used.
        """
        raise AssertionError("Please use dtp_timeout.")

    @property
    def dtp_timeout(self):
        """
        Timeout for data connection.
        """
        return self.factory.dtp_timeout

    @property
    def _timeoutCall(self):
        """
        Return the timeout call.

        Used only for testing.
        """
        return self._TimeoutMixin__timeoutCall

    @property
    def _peer(self):
        """
        Return the remote peer.
        """
        return self.transport.getPeer()

    def connectionMade(self):
        """
        Called when a new command connection was made.
        """
        log(10033,
            _(u'New FTP/FTPS client connection made.'), peer=self._peer)
        self._resetSSLStatus()
        self.state = self.UNAUTH
        self.setTimeout(self.timeOut)
        self.reply(ftp.WELCOME_MSG, self.factory.welcome_message)

    def _resetSSLStatus(self):
        '''Reset SSL/TLS related status.'''
        self._pbsz = False
        self._protected_data_requested = False
        self._protected_command_requested = False

    def connectionLost(self, reason):
        """
        Called when the current command connection was lost.
        """

        if (isinstance(reason, Failure) and
                isinstance(reason.value, SSL.Error)):
            family = reason.value[0][0][1]
            if family == 'SSL3_GET_CLIENT_CERTIFICATE':
                log(10014,
                    _(u'Clients are required to send a valid certificate. '
                      u'Maybe the client did not sent a certificate or '
                      u'the client certificate is not valid.'),
                    avatar=self._avatar, peer=self._peer)

        log(10034,
            _(u'Client FTP/FTPS connection lost.'),
            avatar=self._avatar, peer=self._peer)

        self.cleanupDTP()
        self.setTimeout(None)
        if hasattr(self.shell, 'logout') and self.shell.logout is not None:
            self.shell.logout()
        self.shell = None
        self.transport = None
        # Clean the avatar at the end so that other code can still
        # use it in the cleanup.
        self._avatar = None

    def timeoutConnection(self):
        log(10084,
            _(u'Client FTP/FTPS connection timed out.'),
            avatar=self._avatar, peer=self._peer)
        self.transport.loseConnection()

    def rawDataReceived(self, data):
        '''FTP protocol should not use raw data.'''
        raise AssertionError('FTP protocol should not receive raw data.')

    def lineReceived(self, line):
        '''Reimplement lineReceived so that we can implement logging
        for internal server errors.'''
        self.resetTimeout()
        self.pauseProducing()

        def processFailed(err):
            if err.check(ftp.FTPCmdError):
                self.sendLine(err.value.response())
            elif (err.check(TypeError) and
                  err.value.args[0].find('takes exactly') != -1):
                self.reply(
                    ftp.SYNTAX_ERR, "%s requires an argument." % (cmd,))
            else:
                debug_procees_failure(err, cmd)
                self.reply(ftp.REQ_ACTN_NOT_TAKEN, "internal server error")

        def debug_procees_failure(error, command):
            import traceback
            error_details = traceback.format_exc()
            log(10016, _(
                u'Internal server error. Failed to process the '
                u'requested "%s" FTP command. %s %s' % (
                    command, str(error), error_details)))

        def processSucceeded(result):
            if isinstance(result, tuple):
                self.reply(*result)
            elif result is not None:
                self.reply(result)

        def allDone(ignored):
            if not self.disconnected:
                self.resumeProducing()

        spaceIndex = line.find(' ')
        if spaceIndex != -1:
            cmd = line[:spaceIndex]
            args = (line[spaceIndex + 1:],)
        else:
            cmd = line
            args = ()
        d = defer.maybeDeferred(self.processCommand, cmd, *args)
        d.addCallbacks(processSucceeded, processFailed)
        d.addErrback(debug_procees_failure)

        # XXX It burnsss
        # LineReceiver doesn't let you resumeProducing inside
        # lineReceived atm
        reactor.callLater(0, d.addBoth, allDone)

    def processCommand(self, cmd, *params):
        '''Process FTP commands.

        If FTPS is enabled and secure connections are forced, make sure
        we have a secure channel before executing commands.
        '''
        cmd = cmd.upper()
        if self._debug:
            log(10011,
                _(u'Received command "%s" with "%s".' % (cmd, params)),
                avatar=self._avatar,
                peer=self._peer,
                )

        if cmd in self.PUBLIC_COMMANDS:
            method = getattr(self, "ftp_" + cmd, None)
            if method is not None:
                return method(*params)

        if self.factory.ssl_enabled:
            if cmd in ('USER', 'PASS'):
                if not self.have_valid_authentication_channel:
                    log(10035,
                        _(u'SSL/TLS required on the command channel.'),
                        avatar=self._avatar, peer=self._peer)
                    return SSL_COMMAND_REQUIRED
            elif cmd in ('PASV', 'EPSV', 'PORT', 'EPRT'):
                if (self.factory.ftps_force_secured_data_channel and
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

        result = super(
            FTPProtocol, self).processCommand(cmd, *params)

        if isinstance(result, defer.Deferred):
            def eb_log_unknown_command(failure):
                failure.trap(ftp.CmdNotImplementedError)
                log(10019, _(
                    u'FTP command "%s" with arguments "%s" not implemented '
                    u'by the server.' % (cmd, ' '.join(params))),
                peer=self._peer,
                )
                return failure

            result.addErrback(eb_log_unknown_command)

        return result

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
            ' CCC\n'
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
            self.transport.startTLS(
                self.factory.ssl_context_factory, self.factory)
            self._protected_command_requested = True
            log(10024,
                _(u'Secure command channel successfully initialized.'),
                peer=self._peer)
            return None
        else:
            self._protected_command_requested = False
            return AUTH_BAD

    def ftp_CCC(self):
        '''
        When a server receives the CCC command, it should behave as follows:

        If the server does not accept CCC commands (or does not understand
        them), then a 500 reply should be sent.

        Otherwise, if the control connection is not protected with TLS,
        then a 533 reply should be sent.

        Otherwise, if the server does not wish to allow the control
        connection to be cleared at this time, then a 534 reply should be
        sent.

        Otherwise, the server is accepting the CCC command and should do
        the following:

         o  Send a 200 reply.

         o  Shutdown the TLS session on the socket and leave it open.

         o  Continue the control connection in plaintext, expecting the
            next command from the client to be in plaintext.

         o  Not accept any more PBSZ or PROT commands.  All subsequent
            data transfers must be protected with the current PROT
            settings.
        '''
        if not self.is_ftps_command_active:
            log(10086, _(
                u'Command channel is already cleared.'))
            return CCC_ALREADY

        if self.factory.ftps_force_secured_command_channel:
            log(10087, _(
                u'Server does not allow to clear the command channel.'))
            return CCC_NOT_ALLOWED

        self.reply(CCC_OK)
        self.transport.stopTLS()
        self._protected_command_requested = False
        log(10085, _(
            u'Successfully cleared command channel.'),
            avatar=self._avatar,
            )

    def ftp_CDUP(self):
        '''CHANGE TO PARENT DIRECTORY (CDUP)

        This command is a special case of CWD, and is included to
        simplify the implementation of programs for transferring
        directory trees between operating systems having different
        syntaxes for naming the parent directory.  The reply codes
        shall be identical to the reply codes of CWD.
        '''
        log(10040, _(u'Request to change to parent folder.'), self._avatar)

        defer_result = super(FTPProtocol, self).ftp_CDUP()

        def result_ok(result):
            log(10041,
                _(u'Successfully changed to parent folder.'),
                self._avatar)
            return result

        def result_bad(result):
            log(10042,
                _(u'Failed to change to parent folder.'),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_CWD(self, path):
        '''CHANGE WORKING DIRECTORY (CWD)

        This command allows the user to work with a different
        directory or dataset for file storage or retrieval without
        altering his login or accounting information.  Transfer
        parameters are similarly unchanged.  The argument is a
        pathname specifying a directory or other system dependent
        file group designator.
        '''
        path_name = path.decode('utf-8')
        log(10037,
            _(u'Request to change current folder to "%s".' % path_name),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_CWD(path)

        def result_ok(result):
            log(10038,
                _(u'Current folder successfully changed to "%s".' % (
                    path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10039,
                _(u'Failed to change to folder "%s".' % path_name),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_DELE(self, path):
        '''DELETE (DELE)

        This command causes the file specified in the pathname to be
        deleted at the server site.
        '''
        path_name = path.decode('utf-8')
        log(10043,
            _(u'Request to delete "%s".' % path_name),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_DELE(path)

        def result_ok(result):
            log(10044,
                _(u'Successfully deleted "%s".' % path_name),
                self._avatar)
            return result

        def result_bad(result):
            log(10045,
                _(u'Failed to delete "%s".' % path_name),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_EPRT(self, address):
        '''Request for a extended port connection.

        The EPRT command allows for the specification of an extended address
        for the data connection.  The extended address MUST consist of the
        network protocol as well as the network and transport addresses.  The
        format of EPRT is:

        The following are sample EPRT commands:
            EPRT |1|132.235.1.2|6275|
            EPRT |2|1080::8:800:200C:417A|5282|
        '''
        if self._disable_new_connections:
            return EPSV_ALL_ACTIVE

        separator = address[0]
        address = address.split(separator)
        protocol = address[1]
        ip = address[2]
        port = int(address[3])

        log(10090,
            _(u'Extended address active transfer requested to protocol "%s" '
              u'on address "%s:%d".' % (protocol, ip, port)),
            self._avatar,
            )

        if protocol != '1':
            # For now, only IPV4 is supported.
            return self.reply(EPSV_UNKNOWN_PROTOCOL, '1')

        return self._startActiveDTP(ip=ip, port=port, use_extended=True)

    def ftp_EPSV(self, protocol=None):
        """
        Request for a extended passive connection.

        When the EPSV command is issued with no argument, the server will
        choose the network protocol for the data connection based on the
        protocol used for the control connection.  However, in the case of
        proxy FTP, this protocol might not be appropriate for communication
        between the two servers.  Therefore, the client needs to be able to
        request a specific protocol.  If the server returns a protocol that
        is not supported by the host that will be connecting to the port, the
        client MUST issue an ABOR (abort) command to allow the server to
        close down the listening connection.  The client can then send an
        EPSV command requesting the use of a specific network protocol, as
        follows:

            EPSV<space><net-prt>

        If the requested protocol is supported by the server, it SHOULD use
        the protocol.  If not, the server MUST return the 522 error messages

        The EPSV command can be used with the argument "ALL" to
        inform Network Address Translators that the EPRT command (as well as
        other data commands) will no longer be used.  An example of this
        command follows:

        EPSV ALL

        Upon receipt of an EPSV ALL command, the server MUST reject all data
        connection setup commands other than EPSV - EPRT, PORT, PASV, et

        http://tools.ietf.org/html/rfc2428
        """
        if self._disable_new_connections:
            return EPSV_ALL_ACTIVE

        if protocol:
            if protocol.lower() == 'all':
                self._disable_new_connections = True
                return EPSV_ALL_OK

            if protocol != '1':
                # For now, only IPV4 is supported.
                return self.reply(EPSV_UNKNOWN_PROTOCOL, '1')

        emit("10020", data={"avatar": self._avatar})
        return self._startPassiveDTP(use_extended=True)

    def _startPassiveDTP(self, use_extended):
        """
        Start a passive data transport channel.
        """
        # if we have a DTP port set up, lose it.
        self.cleanupDTP()

        self.dtpFactory = DTPFactory(pi=self)
        self.dtpPort = self._getPassivePort(self.dtpFactory)

        if not self.dtpPort:
            self.cleanupDTP()
            data = {
                "avatar": self._avatar,
                "port_range": str(self.passive_port_range),
            }
            emit("10015", data=data)
            return ftp.CANT_OPEN_DATA_CNX
        else:
            host = self.transport.getHost().host
            port = self.dtpPort.getHost().port

            if use_extended:
                mode = ftp.ENTERING_EPSV_MODE
                encoded_port = str(port)
            else:
                mode = ftp.ENTERING_PASV_MODE
                encoded_port = ftp.encodeHostPort(host, port)

            self.reply(mode, encoded_port)

            data = {
                "avatar": self._avatar,
                "port": str(port),
            }
            emit("10022", data=data)
            # We add a blank callback since we don't need to wait for
            # DTP connection to start as we are the one starting the
            # connection.
            # A callback is required to avoid errors when deferred is called
            # and it has no callbacks.
            # The deferred is returned so that the FTP protocol will only
            # continue after the client connects.
            return self.dtpFactory.deferred.addCallback(lambda ign: None)

    def _getPassivePort(self, dtp_factory):
        """
        Return a port for passive access, using L{self.passive_port_range}
        attribute.

        Return None if no port could be obtained.
        """
        for port_number in self.passive_port_range:
            try:
                if self._protected_data_requested:
                    tls_factory = ChevahTLSMemoryBIOFactory(
                        contextFactory=self.factory.ssl_context_factory,
                        isClient=False,
                        wrappedFactory=dtp_factory)
                    dtp_factory = tls_factory

                dtpPort = self.listenFactory(port_number, dtp_factory)
            except error.CannotListenError:
                continue
            else:
                return dtpPort

        # If we can not obtain a port, just return None.
        return None

    def _startActiveDTP(self, ip, port, use_extended):
        """
        Initialize an active data transport channel.
        """
        # if we have a DTP port set up, lose it.
        self.cleanupDTP()

        self.dtpFactory = DTPFactory(
            pi=self, peerHost=self.transport.getPeer().host)

        if self._protected_data_requested:
            # It is strange, but for active connection the SSL
            # layer is still seen as a server.
            factory = ChevahTLSMemoryBIOFactory(
                contextFactory=self.factory.ssl_context_factory,
                isClient=False,
                wrappedFactory=self.dtpFactory,
                )
        else:
            factory = self.dtpFactory

        self.dtpPort = reactor.connectTCP(ip, port, factory)

        if use_extended:
            mode = ENTERING_EPRT_MODE
        else:
            mode = ftp.ENTERING_PORT_MODE

        def connected(ignored, mode):
            data = {
                "avatar": self._avatar,
                "address": ip,
                "port": str(port),
            }
            emit("10063", data=data)
            return mode

        def connFailed(err):
            data = {
                "avatar": self._avatar,
            }
            emit("10064", data=data)
            err.trap(ftp.PortConnectionError)
            return ftp.CANT_OPEN_DATA_CNX

        self.dtpFactory.deferred.addCallback(connected, mode)
        self.dtpFactory.deferred.addErrback(connFailed)
        return self.dtpFactory.deferred

    def cleanupDTP(self, reason=None):
        """
        call when DTP connection exits.
        """
        if not self.dtpFactory:
            return

        old_dtpPort = self.dtpPort
        self.dtpPort = None
        if old_dtpPort:
            if ftp.interfaces.IListeningPort.providedBy(old_dtpPort):
                old_dtpPort.stopListening()
            elif ftp.interfaces.IConnector.providedBy(old_dtpPort):
                old_dtpPort.disconnect()
            else:
                assert False, (
                    "dtpPort should be an IListeningPort or IConnector, "
                    "instead is %r" % (old_dtpPort,))

        self.dtpFactory.stopFactory()
        self.dtpFactory = None

    def ftp_LIST(self, path='.'):
        '''LIST (LIST)

        This command causes a list to be sent from the server to the
        passive DTP.  If the pathname specifies a directory or other
        group of files, the server should transfer a list of files
        in the specified directory.  If the pathname specifies a
        file then the server should send current information on the
        file.  A null argument implies the user's current working or
        default directory.  The data transfer is over the data
        connection in type ASCII or type EBCDIC.  (The user must
        ensure that the TYPE is appropriately ASCII or EBCDIC).
        Since the information on a file may vary widely from system
        to system, this information may be hard to use automatically
        in a program, but may be quite useful to a human user.
        '''
        path_name = path.decode('utf-8')
        log(10046,
            _(u'Listing folder "%s".' % (path_name)),
            self._avatar)

        # bug in FireFTP
        if path == "-al":
            path = ''

        # bug in BareFTP
        if path == "-La":
            path = ''

        def result_ok(result):
            log(10047,
                _(u'Folder "%s" successfully listed.' % (path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10048,
                _(u'Failed to list folder "%s".' % (path_name)),
                self._avatar)
            return result

        defer_result = super(FTPProtocol, self).ftp_LIST(path)
        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_MDTM(self, path):
        '''File Modification Time (MDTM)

        The FTP command, MODIFICATION TIME (MDTM), can be used to determine
        when a file in the server NVFS was last modified.  This command has
        existed in many FTP servers for many years, as an adjunct to the REST
        command for STREAM mode, thus is widely available.  However, where
        supported, the "modify" fact that can be provided in the result from
        the new MLST command is recommended as a superior alternative.
        http://tools.ietf.org/html/rfc3659
        '''
        path_name = path.decode('utf-8')
        log(10049,
            _(u'Getting modification date for "%s".' % (path_name)),
            self._avatar)
        defer_result = super(FTPProtocol, self).ftp_MDTM(path)

        def result_ok(result):
            log(10050,
                _(u'Successfully got modification date for "%s".' % (
                    path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10051,
                _(u'Failed to get modification date for "%s".' % (path_name)),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_MKD(self, path):
        '''MAKE DIRECTORY (MKD)

        This command causes the directory specified in the pathname
        to be created as a directory (if the pathname is absolute)
        or as a subdirectory of the current working directory (if
        the pathname is relative).
        '''
        path_name = path.decode('utf-8')
        log(10052,
            _(u'Creating folder "%s".' % (path_name)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_MKD(path)

        def result_ok(result):
            log(10053,
                _(u'Successfully created folder "%s".' % (path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10054,
                _(u'Failed to create folder "%s".' % (path_name)),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def _ftp_MODE(self, mode):
        '''TRANSFER MODE (MODE)

        The argument is a single Telnet character code specifying
        the data transfer modes described in the Section on
        Transmission Modes.

        The following codes are assigned for transfer modes:
           S - Stream
           B - Block
           C - Compressed
        The default transfer mode is Stream.

        Not implemented yet.
        '''

    def ftp_NLST(self, path=''):
        '''NAME LIST (NLST)

        This command causes a directory listing to be sent from
        server to user site.  The pathname should specify a
        directory or other system-specific file group descriptor; a
        null argument implies the current directory.  The server
        will return a stream of names of files and no other
        information.  The data will be transferred in ASCII or
        EBCDIC type over the data connection as valid pathname
        strings separated by <CRLF> or <NL>.  (Again the user must
        ensure that the TYPE is correct.)  This command is intended
        to return information that can be used by a program to
        further process the files automatically.  For example, in
        the implementation of a "multiple get" function.
        '''
        path_name = path.decode('utf-8')
        log(10055,
            _(u'Listing names for folder "%s".' % (path_name)),
            self._avatar)

        if self.dtpInstance is None or not self.dtpInstance.isConnected:
            return defer.fail(
                ftp.BadCmdSequenceError('must send PORT or PASV before RETR'))

        try:
            segments = ftp.toSegments(self.workingDirectory, path)
        except ftp.InvalidPath:
            return defer.fail(ftp.FileNotFoundError(path))

        def cbList(results):
            """
            Send, line by line, each file in the directory listing, and then
            close the connection.

            @type results: A C{list} of C{tuple}. The first element of each
                C{tuple} is a C{str} and the second element is a C{list}.
            @param results: The names of the files in the directory.

            @rtype: C{tuple}
            @return: A C{tuple} containing the status code for a successful
                transfer.
            """
            self.reply(ftp.DATA_CNX_ALREADY_OPEN_START_XFR)
            for (name, ignored) in results:
                self.dtpInstance.sendLine(name)
            self.dtpInstance.transport.loseConnection()
            return (ftp.TXFR_COMPLETE_OK,)

        def cbGlob(results):
            import fnmatch
            self.reply(ftp.DATA_CNX_ALREADY_OPEN_START_XFR)
            for (name, ignored) in results:
                if fnmatch.fnmatch(name, segments[-1]):
                    self.dtpInstance.sendLine(name)
            self.dtpInstance.transport.loseConnection()
            return (ftp.TXFR_COMPLETE_OK,)

        def listErr(results):
            """
            RFC 959 specifies that an NLST request may only return directory
            listings. Thus, send nothing and just close the connection.

            @type results: L{Failure}
            @param results: The L{Failure} wrapping a L{FileNotFoundError}
                that occurred while trying to list the contents of a
                nonexistent directory.

            @rtype: C{tuple}
            @returns: A C{tuple} containing the status code for a successful
                transfer.
            """
            log(10057,
                _(u'Failed to list names for folder "%s".' % (path_name)),
                self._avatar)
            self.reply(ftp.DATA_CNX_ALREADY_OPEN_START_XFR)
            self.dtpInstance.transport.loseConnection()
            return (ftp.TXFR_COMPLETE_OK,)

        # XXX This globbing may be incomplete: see #4181
        if segments and (
            '*' in segments[-1] or '?' in segments[-1] or
            ('[' in segments[-1] and ']' in segments[-1])):
            d = self.shell.list(segments[:-1])
            d.addCallback(cbGlob)
        else:
            d = self.shell.list(segments)
            d.addCallback(cbList)
            # self.shell.list will generate an error if the path is invalid
            d.addErrback(listErr)
        defer_result = d

        def result_ok(result):
            log(10056,
                _(u'Successfully listed names for folder "%s".' % (
                    path_name)),
                self._avatar)
            return result

        defer_result.addCallback(result_ok)
        return defer_result

    def ftp_NOOP(self):
        '''NOOP (NOOP)

        This command does not affect any parameters or previously
        entered commands. It specifies no action other than that the
        server send an OK reply.
        '''
        return (ftp.CMD_OK,)

    def ftp_OPTS(self, option):
        '''Handle OPTS command.

        http://tools.ietf.org/html/draft-ietf-ftpext-utf-8-option-00
        '''
        if option.lower().startswith('utf8'):
            # Filezilla uses OPTS UTF8 ON ... but by RFC it should be only
            # OPTS UTF8 ... so just look for starting.
            return self.reply(OPTS_UTF8_OK)
        return self.reply(OPTS_NOT_IMPLEMENTED)

    def ftp_PASV(self):
        '''PASSIVE (PASV)

        This command requests the server-DTP to "listen" on a data
        port (which is not its default data port) and to wait for a
        connection rather than initiate one upon receipt of a
        transfer command.  The response to this command includes the
        host and port address this server is listening on.
        '''
        if self._disable_new_connections:
            return EPSV_ALL_ACTIVE

        emit("10061", data={"avatar": self._avatar})
        return self._startPassiveDTP(use_extended=False)

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
        if self._disable_new_connections:
            return EPSV_ALL_ACTIVE

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

        return self._startActiveDTP(ip=ip, port=port, use_extended=False)

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

    def ftp_PWD(self):
        '''PRINT WORKING DIRECTORY (PWD)

        This command causes the name of the current working
        directory to be returned in the reply.
        '''
        log(10065,
                _(u'Requesting current folder.'), self._avatar)
        path = self.workingDirectory
        return (ftp.PWD_REPLY, path)

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

    def ftp_RETR(self, path):
        '''RETRIEVE (RETR)

        This command causes the server-DTP to transfer a copy of the
        file, specified in the pathname, to the server- or user-DTP
        at the other end of the data connection.  The status and
        contents of the file at the server site shall be unaffected.
        '''
        path_name = path.decode('utf-8')
        log(10068,
            _(u'Retrieving file "%s".' % (path_name)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_RETR(path)

        def log_result(result):
            if result[0] == ftp.TXFR_COMPLETE_OK:
                log(10069,
                    _(u'Successfully retrieved file "%s".' % (path_name)),
                    self._avatar)
            else:
                log(10070,
                    _(u'Failed to retrieve file "%s".' % (path_name)),
                    self._avatar)
            if len(result) > 1:
                result = (result[0], result[1].encode('utf-8'))
            return result

        defer_result.addCallback(log_result)
        return defer_result

    def ftp_RMD(self, path):
        '''REMOVE DIRECTORY (RMD)

        This command causes the directory specified in the pathname
        to be removed as a directory (if the pathname is absolute)
        or as a subdirectory of the current working directory (if
        the pathname is relative).
        '''
        path_name = path.decode('utf-8')
        log(10071,
            _(u'Deleting folder "%s".' % (path_name)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_RMD(path)

        def result_ok(result):
            log(10072,
                _(u'Successfully deleted folder "%s".' % (path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10073,
                _(u'Failed to delete folder "%s".' % (path_name)),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def _ftp_RNFR(self, from_name):
        '''RENAME FROM (RNFR)

        We only log RNTO. This is here just for documentation.

        This command specifies the old pathname of the file which is
        to be renamed.  This command must be immediately followed by
        a "rename to" command specifying the new file pathname
        '''

    def ftp_RNTO(self, to_name):
        '''RENAME TO (RNTO)

        This command specifies the new pathname of the file
        specified in the immediately preceding "rename from"
        command.  Together the two commands cause a file to be
        renamed.
        '''
        to_path = to_name.decode('utf-8')
        from_path = self._fromName.decode('utf-8')
        log(10074,
            _(u'Renaming "%s" to "%s".' % (from_path, to_path)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_RNTO(to_name)

        def result_ok(result):
            log(10075,
                _(u'Successfully renamed "%s" to "%s".' % (
                    from_path, to_path)),
                self._avatar)
            return result

        def result_bad(result):
            log(10076,
                _(u'Failed to rename "%s" to "%s".' % (from_path, to_path)),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_SIZE(self, path):
        '''File SIZE

        The FTP command, SIZE OF FILE (SIZE), is used to obtain the transfer
        size of a file from the server-FTP process.  This is the exact number
        of octets (8 bit bytes) that would be transmitted over the data
        connection should that file be transmitted.  This value will change
        depending on the current STRUcture, MODE, and TYPE of the data
        connection or of a data connection that would be created were one
        created now.  Thus, the result of the SIZE command is dependent on
        the currently established STRU, MODE, and TYPE parameters.

        The SIZE command returns how many octets would be transferred if the
        file were to be transferred using the current transfer structure,
        mode, and type.  This command is normally used in conjunction with
        the RESTART (REST) command when STORing a file to a remote server in
        STREAM mode, to determine the restart point.  The server-PI might
        need to read the partially transferred file, do any appropriate
        conversion, and count the number of octets that would be generated
        when sending the file in order to correctly respond to this command.
        Estimates of the file transfer size MUST NOT be returned; only
        precise information is acceptable.

        http://tools.ietf.org/html/rfc3659
        '''
        path_name = path.decode('utf-8')
        log(10080,
            _(u'Retrieving size for "%s".' % (path_name)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_SIZE(path)

        def result_ok(result):
            log(10081,
                _(u'Successfully retrieved size for "%s".' % (path_name)),
                self._avatar)
            return result

        def result_bad(result):
            log(10082,
                _(u'Failed to retrieve size for "%s".' % (path_name)),
                self._avatar)
            return result

        defer_result.addCallbacks(result_ok, result_bad)
        return defer_result

    def ftp_STOR(self, path):
        '''STORE (STOR)

        This command causes the server-DTP to accept the data
        transferred via the data connection and to store the data as
        a file at the server site.  If the file specified in the
        pathname exists at the server site, then its contents shall
        be replaced by the data being transferred.  A new file is
        created at the server site if the file specified in the
        pathname does not already exist.
        '''
        path_name = path.decode('utf-8')
        log(10077,
            _(u'Storing file "%s".' % (path_name)),
            self._avatar)

        defer_result = super(FTPProtocol, self).ftp_STOR(path)

        def log_result(result):
            if result[0] == ftp.TXFR_COMPLETE_OK:
                log(10078,
                    _(u'Successfully stored file "%s".' % (path_name)),
                    self._avatar)
            else:
                log(10079,
                    _(u'Failed to store file "%s".' % (path_name)),
                    self._avatar)
            if len(result) > 1:
                result = (result[0], result[1].encode('utf-8'))
            return result

        defer_result.addCallback(log_result)
        return defer_result

    def _ftp_STRU(self, structure):
        '''FILE STRUCTURE (STRU)

        The argument is a single Telnet character code specifying
        file structure described in the Section on Data
        Representation and Storage.

        The following codes are assigned for structure:
           F - File (no record structure)
           R - Record structure
           P - Page structure
        The default structure is File.

        Not implemented yet.
        '''

    def _ftp_SYST(self, mode):
        '''SYSTEM (SYSTE)

        RFC details not found.

        Not logged yet.
        '''

    def _ftp_TYPE(self, type):
        '''REPRESENTATION TYPE (TYPE)

        The argument specifies the representation type as described
        in the Section on Data Representation and Storage.  Several
        types take a second parameter.  The first parameter is
        denoted by a single Telnet character, as is the second
        Format parameter for ASCII and EBCDIC; the second parameter
        for local byte is a decimal integer to indicate Bytesize.
        The parameters are separated by a <SP> (Space, ASCII code
        32).

        Not logged yet.
        '''

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
                    raise AuthorizationError()

            def cb_ssl_authentication_done(result):
                '''Callback for handling finalized SSL login.'''
                (interface, avatar, logout) = result
                self._setupSession(avatar, logout)
                # Delete temporary _user variable used between USER and PASS
                # commands.
                del self._user
                return USR_LOGGED_IN_SSL_PROCEED

            credentials = FTPSSSLCertificateCredentials(
                username=username_utf8,
                certificate=peer_certificate,
                peer=self._peer,
                )
            defered_login = self.factory.portal.login(
                credentials, None, IFTPShell)
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
            raise AuthorizationError()

        def cb_password_authentication_done(result):
            '''Callback for handling finalized login.'''
            (interface, avatar, logout) = result
            self._setupSession(avatar, logout)
            # Delete temporary _user variable used between USER and PASS
            # commands.
            del self._user
            return ftp.USR_LOGGED_IN_PROCEED

        if self.is_ftps_command_active:
            credentials_class = FTPSPasswordCredentials
        else:
            credentials_class = FTPPasswordCredentials

        credentials = credentials_class(
            username=username,
            password=password,
            peer=self._peer,
            )
        defered_login = self.factory.portal.login(
            credentials, None, IFTPShell)
        defered_login.addCallbacks(
            cb_password_authentication_done, cb_password_error)
        return defered_login

    def _setupSession(self, avatar, logout):
        '''Prepare the FTP session after successful login.'''
        self.shell = avatar
        self._avatar = FTPAvatar(name=self._user, peer=self._peer)
        self.logout = logout
        self.workingDirectory = []
        self.state = self.AUTHED
        log(10059,
            _(u'User successfully loged.'),
            avatar=self._avatar)

    def type_U(self, code):
        '''TYPE U is equivalent with A.

        UTF-8 RFC http://tools.ietf.org/html/draft-klensin-ftp-typeu-00
        '''
        if code == '' or code == 'N':
            self.binary = False
            return (ftp.TYPE_SET_OK, 'U' + code)
        else:
            return defer.fail(ftp.CmdArgSyntaxError(code))

    @property
    def dtpInstance(self):
        """
        Reference to data channel protocol instance.

        FTPProtocol.dtpInstance is used to signal that a PORT/PASV command
        was requeted and to operate the data channel.
        """
        if not self.dtpFactory:
            return None
        else:
            return self.dtpFactory.dtpInstance


class FTPOverflowProtocol(LineReceiver):
    """
    FTP mini-protocol for when there are too many connections.
    """

    @property
    def _peer(self):
        """
        Return a remote peer.
        """
        return self.transport.getPeer()

    def connectionMade(self):
        emit(u'10091', data={'peer': self._peer})
        self.sendLine(RESPONSE[ftp.TOO_MANY_CONNECTIONS])
        self.transport.loseConnection()


class FTPInternalErrorProtocol(LineReceiver):
    """
    FTP mini-protocol for when an internal server error occured while
    initializing the actual protocol.
    """

    details = "Internal server error."

    @property
    def _peer(self):
        """
        Return a remote peer.
        """
        return self.transport.getPeer()

    def connectionMade(self):
        data = {
            'peer': self._peer,
            'details': self.details,
        }
        emit(u'10032', data=data)
        self.sendLine(
            RESPONSE[ftp.REQ_ACTN_NOT_TAKEN] % ("Internal server error."))
        self.transport.loseConnection()


class FTPSIProtocol(FTPProtocol):
    """
    Implicit FTPS protocol.
    """

    @property
    def is_ftps_command_active(self):
        """
        Data channel is always secured in FTPIS.
        """
        return True

    def have_valid_authentication_channel(self):
        """
        Data channel is always secured in FTPIS.
        """
        return True

    def ftp_CCC(self):
        """
        CCC command is not allowed in FTPIS.
        """
        return CCC_NOT_ALLOWED


class DTPProtocol(ftp.DTP, policies.TimeoutMixin, object):
    """
    This is the protocol used over the data channel.
    """

    def __init__(self, dtp_factory, on_close):
        """
        :param factory: Reference to parent DTP factory.
        :param pi: Reference to FTP protocol.
        :param on_close: Function to call when connection is closed.
        """
        self.factory = dtp_factory
        self._onClose = on_close
        self._host = None
        self._peer = None

        # Using self.transport.loseConnection() we can not set a status why
        # connection was closed and Twisted will just assume that connection
        # was closed in the "clean" way.
        # This is why we use this flag to check that connection was
        # closed due to a timeout.
        self._timeout_called = None

        self._onConnLost = defer.Deferred()

    @property
    def _timeoutCall(self):
        """
        Return the timeout call.

        Used only for testing.
        """
        return self._TimeoutMixin__timeoutCall

    @property
    def host(self):
        """
        Address of the local connection.
        """
        return self._host

    @property
    def peer(self):
        """
        Address of the remote connection.
        """
        return self._peer

    def connectionMade(self):
        """
        Called when data channel is connected.
        """
        self._host = self.transport.getHost()
        self._peer = self.transport.getPeer()
        self.isConnected = True
        self.factory.deferred.callback(None)
        self._buffer = []
        self.setTimeout(self.factory.dtp_timeout)

    def connectionLost(self, reason):
        """
        Called when data channel was closed.
        """
        data = {
            "avatar": self.factory.pi._avatar,
            "host_address": self.host.host,
            "host_port": str(self.host.port),
            "peer_address": self.peer.host,
            "peer_port": str(self.peer.port),
        }
        emit("10030", data=data)
        self.setTimeout(None)
        self.isConnected = False

        if self._timeout_called:
            reason = error.ConnectionLost("Data connection timeout")
            self._onConnLost.errback(reason)
        else:
            self._onConnLost.callback(None)

        self._onClose(reason=reason)

    def timeoutConnection(self):
        """
        Called when data connection times out.
        """
        data = {
            "avatar": self.factory.pi._avatar,
            "host_address": self.host.host,
            "host_port": str(self.host.port),
            "peer_address": self.peer.host,
            "peer_port": str(self.peer.port),
        }
        emit("10031", data=data)
        # setTimeout should be called later by loseConnection... but
        # we can also do it now.
        self.setTimeout(None)
        self._timeout_called = True
        self.transport.loseConnection()

    def sendLine(self, line):
        """
        Send a line using network new line.
        """
        self.write(line + '\r\n')

    def resetTimeout(self):
        """
        Reset timeout for data and control protocols.
        """
        self.factory.pi.resetTimeout()
        super(DTPProtocol, self).resetTimeout()

    def write(self, data):
        self.resetTimeout()
        return super(DTPProtocol, self).write(data)

    def dataReceived(self, bytes):
        self.resetTimeout()
        return super(DTPProtocol, self).dataReceived(bytes)


class DTPFactory(ftp.DTPFactory, object):
    """
    The DTPFactory used for listening to incoming data connection.

    It is designed to accept a single connection, and to stop listening
    for new connections once the first connection was closed.
    One DTPFactory is initialized for each data connection and will have
    a single DTPProtocol.

    A `factory` and `protocol` was used to integrate with general Twisted
    conventions for handling connections.
    """

    protocol = DTPProtocol

    def __init__(self, pi, peerHost=None, reactor=None):
        super(DTPFactory, self).__init__(
            pi=pi, peerHost=peerHost, reactor=reactor)
        self.setTimeout(self.dtp_timeout)
        self.dtpInstance = None

    def buildProtocol(self, addr):
        if self._state is not self._IN_PROGRESS:
            return None
        self._state = self._FINISHED

        self.cancelTimeout()
        p = self.protocol(dtp_factory=self, on_close=self.pi.cleanupDTP)
        self.dtpInstance = p
        return p

    def stopFactory(self):
        if self.dtpInstance is not None:
            self.dtpInstance = None
        self.cancelTimeout()

    @property
    def dtp_timeout(self):
        """
        Data channel idle timeout value
        """
        return self.pi.dtp_timeout
