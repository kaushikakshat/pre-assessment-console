import os

SECRET_ENV = ("CREDENTIALS_PUBLIC_KEY", "CREDENTIALS_PRIVATE_KEY", "ZAP_API_KEY", "EGRESS_TOKEN", "SECRET_KEY", "DATABASE_URL")


def clean_env():
    """Environment for child processes (nmap, testssl.sh): ours minus every secret."""
    return {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
