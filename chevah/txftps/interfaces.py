# Copyright (c) 2012 Adi Roiban.
# See LICENSE for details.
'''Common interfaces used by Chevah products.'''

from zope.interface import Interface, Attribute


class ICredentials(Interface):
    """
    Hold credentials as provides by clients while authentication using
    various services.

    Provides attributes shared by all credential types.
    """
    username = Attribute(
        '''
        Username for which the authentication is requested.
        ''')

    peer = Attribute(
        '''
        IP address and port number for the remote peer requesting
        authentication.
        ''')

    kind_name = Attribute(
        '''
        Human readable name for the type of these credentials.

        Example: `"password"`, `"ssh key"`, `"ssl certificate"`... etc
        ''')


class IPasswordCredentials(ICredentials):
    """
    Credentials based on password.
    """
    password = Attribute(
        '''
        Password associated with the username.
        ''')


class ISSLCertificateCredentials(ICredentials):
    """
    Credentials base on SSL certificate.
    """

    certificate = Attribute(
        '''
        pyOpenSSL certificate object.
        ''')


class IFTPPasswordCredentials(IPasswordCredentials):
    '''Marker interface for a password based credentials obtained via FTP.'''


class IFTPSPasswordCredentials(IPasswordCredentials):
    '''Marker interface for a password based credentials obtained via FTPS.'''


class IFTPSSSLCertificateCredentials(ISSLCertificateCredentials):
    '''Interface for SSL certificate based credentials used for FTPS.'''
