import time

import logging
from logging.handlers import TimedRotatingFileHandler

# format the log entries
from typing import re

formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')

handler = TimedRotatingFileHandler('/Users/lucas/PycharmProjects/NetworkDNSDHCP/Log/logfile.log',
                                   when='midnight',
                                   backupCount=10)
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# generate example messages
for i in range(100):
    time.sleep(1)
    logger.debug('debug message')
    logger.info('informational message')
    logger.warning('warning')
    logger.error('error message')
    logger.critical('critical failure')

# Other way
log_format = "%(asctime)s - %(levelname)s - %(message)s"
log_level = 10
handler = TimedRotatingFileHandler("dns_dhcp.db", when="midnight", interval=1)
handler.setLevel(log_level)
formatter = logging.Formatter(log_format)
handler.setFormatter(formatter)

# add a suffix which you want
handler.suffix = "%Y%m%d"

# need to change the extMatch variable to match the suffix for it
handler.extMatch = re.compile(r"^\d{8}$")

# finally add handler to logger
logger.addHandler(handler)
