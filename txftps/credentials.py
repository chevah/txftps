from zope.interface import implements

from twisted.cred.credentials import ICredentials


class IUsernameSSLCertificate(ICredentials):
    """I encapsulate a username and a SSL certificate."""

    def checkCertificate(certificate):
        """Validate these credentials against the attached certificate.

        Return True if certificate's CN is the same as username.
        """


class UsernameSSLCertificate:
    implements(IUsernameSSLCertificate)

    def __init__(self, username, certificate):
        self.username = username
        self.certificate = certificate

    def checkCertificate(self, certificate):
        if not certificate:
            return False

        subject = certificate.get_subject()

        if not subject:
            return False

        common_name = subject.commonName

        if common_name is None:
            return False

        if self.username == common_name:
            return True
        else:
            return False
