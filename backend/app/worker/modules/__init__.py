from . import exposed, finger, headers, ports, reach, tls

MODULES = {"reach": reach.run, "ports": ports.run, "tls": tls.run, "headers": headers.run, "exposed": exposed.run,
           "finger": finger.run}
TIMEOUTS = {"ports": 180}  # seconds; default 120
