import logging
import logging.handlers as handlers
import time

logger = logging.getLogger('my_app')
logger.setLevel(logging.INFO)

logHandler = handlers.TimedRotatingFileHandler('timed_app.log', when='midnight', backupCount=0)
# logHandler = handlers.TimedRotatingFileHandler('timed_app.log', when='M', interval=1, backupCount=0)
logHandler.namer = lambda name: name + ".db"
logHandler.setLevel(logging.INFO)
logger.addHandler(logHandler)

def main():
    while True:
        time.sleep(1)
        logger.info("A Sample Log Statement")

main()