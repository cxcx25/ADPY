import re
from datetime import datetime, timedelta
from pytz import timezone, UTC
import ldap

DOMAIN_MAPPINGS = {
    'el': 'ELCORP.GROUP',
    'lux': 'LUXGROUP.NET',
    'ess': 'us.essilor.pvt'
}

def format_datetime(dt):
    if not dt:
        return "N/A"
    if isinstance(dt, str):
        try:
            dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S%z')
        except ValueError:
            try:
                dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S.%f%z')
            except ValueError:
                return dt
    return dt.strftime('%m/%d/%Y %I:%M:%S %p').lstrip("0").replace("/0", "/")


def get_domain_credentials(domain):
    with open("credentials.txt", "r") as file:
        for line in file:
            match = re.match(r"^" + domain + r"\s*:\s*user=([^;]+);\s*password=(.+)$", line.strip())
            if match:
                username, password = match.groups()
                return username, password
    raise ValueError(f"Credentials not found for {domain}")


def get_domain_controller(alias):
    full_domain = DOMAIN_MAPPINGS.get(alias.lower())
    if not full_domain:
        raise ValueError(f"Invalid domain alias: {alias}")

    dc_address = f'ldap://{full_domain}'
    try:
        admin_user, admin_pass = get_domain_credentials(alias)
        ldap_conn = ldap.initialize(dc_address)
        ldap_conn.simple_bind_s(f"{admin_user}@{full_domain}", admin_pass)
        return ldap_conn
    except Exception as e:
        raise ConnectionError(f"Failed to connect to domain controller: {str(e)}")
