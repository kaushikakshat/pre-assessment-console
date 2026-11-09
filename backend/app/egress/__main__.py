import asyncio
import os

from app.egress.proxy import serve

asyncio.run(serve(token=os.environ["EGRESS_TOKEN"]))
