from zope.interface import implements

from twisted.cred.checkers import ICredentialsChecker
from twisted.internet import defer, error
from chevah.txftps.interfaces import (
    IPasswordCredentials,
    ISSLCertificateCredentials,
    )


class InMemoryPassword(object):
    implements(ICredentialsChecker)
    credentialInterfaces = IPasswordCredentials,

    def __init__(self, database):
        self._database = database

    def requestAvatarId(self, credentials):
        if not credentials.password:
            return defer.fail(error.UnauthorizedLogin())

        for username, password in self._database:
            if username == credentials.username:
                if password == credentials.password:
                    return username
                else:
                    defer.fail(error.UnauthorizedLogin())

        return defer.fail(error.UnauthorizedLogin())


class SSLCertificateChecker(object):
    implements(ICredentialsChecker)
    credentialInterfaces = ISSLCertificateCredentials,

    def requestAvatarId(self, credentials):

        if not credentials.certificate:
            return defer.fail(error.UnauthorizedLogin())

        subject = credentials.certificate.get_subject()

        if not subject:
            return defer.fail(error.UnauthorizedLogin())

        common_name = subject.commonName

        if common_name is None:
            return defer.fail(error.UnauthorizedLogin())

        if credentials.username == common_name:
            return credentials.username
        else:
            return defer.fail(error.UnauthorizedLogin())
