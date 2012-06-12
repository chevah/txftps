from twisted.python import log as twisted_log


def _(message):
    return message


def log(log_id, message, avatar=None, peer=None):
    twisted_log.msg('%d - %s' % (log_id, message))
