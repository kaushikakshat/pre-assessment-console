from . import access, api, auth, cms, config, crawl, cval, dast, exposed, finger, headers, ports, reach, tls

MODULES = {"reach": reach.run, "ports": ports.run, "tls": tls.run, "headers": headers.run, "exposed": exposed.run,
           "finger": finger.run, "crawl": crawl.run, "dast": dast.run, "api": api.run, "auth": auth.run,
           "access": access.run, "cval": cval.run, "cms": cms.run, "config": config.run}
TIMEOUTS = {"ports": 180}  # seconds; default 120. Engine modules run to their budget stage deadline instead.
