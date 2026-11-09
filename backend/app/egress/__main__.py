import asyncio
import os

from app.core.startup import validate_env
from app.egress.proxy import serve

validate_env("egress")

asyncio.run(serve(token=os.environ["EGRESS_TOKEN"]))
