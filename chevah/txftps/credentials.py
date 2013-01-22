"""
Credentials used by Chevah project.
"""
from zope.interface import implements

from chevah.txftps.interfaces import (
    ICredentials,
    IFTPPasswordCredentials,
    IFTPSPasswordCredentials,
    IFTPSSSLCertificateCredentials,
    IPasswordCredentials,
    ISSLCertificateCredentials,
    )


class CredentialsBase(object):
    """
    Base class for credentials used in the server.
    """

    implements(ICredentials)

    def __init__(self, username, peer=None):
        assert type(username) is unicode
        self.username = username
        self.peer = peer

    @property
    def kind_name(self):
        raise NotImplementedError()


class PasswordCredentials(CredentialsBase):
    """
    Credentials based on password.
    """
    implements(IPasswordCredentials)

    def __init__(self, password=None, token=None, *args, **kwargs):
        super(PasswordCredentials, self).__init__(*args, **kwargs)
        if password:
            assert type(password) is unicode
        self.password = password

    @property
    def kind_name(self):
        return u'password'


class FTPPasswordCredentials(PasswordCredentials):
    '''Marker class for password based credentials used with FTP.'''
    implements(IFTPPasswordCredentials)


class FTPSPasswordCredentials(PasswordCredentials):
    '''Marker class for password based credentials used with FTPS.'''
    implements(IFTPSPasswordCredentials)


class SSLCertificateCredentials(CredentialsBase):
    """
    A SSL certificate key based credentials.
    """

    implements(ISSLCertificateCredentials)

    def __init__(self, certificate=None, *args, **kwargs):
        super(SSLCertificateCredentials, self).__init__(*args, **kwargs)
        self.certificate = certificate

    @property
    def kind_name(self):
        return u'ssl certificate'


class FTPSSSLCertificateCredentials(SSLCertificateCredentials):
    """
    A SSL certificate key based credentials for FTPS.
    """

    implements(IFTPSSSLCertificateCredentials)
