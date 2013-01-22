from twisted.python import log as twisted_log


def _(message):
    return message


def log(log_id, message, avatar=None, peer=None):
    twisted_log.msg('%s - %s' % (str(log_id), message))


def emit(signal_id, data):
    twisted_log.msg('%s - %s' % (str(signal_id), str(data)))
