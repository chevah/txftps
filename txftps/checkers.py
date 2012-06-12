from zope.interface import implements

from twisted.cred.checkers import ICredentialsChecker
from txftps.credentials import IUsernameSSLCertificate


class SSLCertificateChecker(object):
    implements(ICredentialsChecker)
    credentialInterfaces = IUsernameSSLCertificate,

    def requestAvatarId(self, credentials):
        return credentials.checkCertificate(credentials.certificate)
