import asyncio
import logging
import os

from app.core.startup import validate_env
from app.egress.proxy import serve

logging.basicConfig(level=logging.INFO)
validate_env("egress")

asyncio.run(serve(token=os.environ["EGRESS_TOKEN"]))
