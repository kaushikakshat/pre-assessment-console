import logging
import time

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("worker")

if __name__ == "__main__":
    log.info("worker started")  # stub; real loop arrives in task B4
    while True:
        time.sleep(30)
