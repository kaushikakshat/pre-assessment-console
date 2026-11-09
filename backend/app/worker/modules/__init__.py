from . import api, crawl, dast, exposed, finger, headers, ports, reach, tls

MODULES = {"reach": reach.run, "ports": ports.run, "tls": tls.run, "headers": headers.run, "exposed": exposed.run,
           "finger": finger.run, "crawl": crawl.run, "dast": dast.run, "api": api.run}
TIMEOUTS = {"ports": 180}  # seconds; default 120. Engine modules run to their budget stage deadline instead.
