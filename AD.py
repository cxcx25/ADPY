import re
import os
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, SIMPLE
from datetime import datetime, timedelta
from pytz import timezone, UTC
import sys

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
    server = Server(dc_address, get_info=ALL, connect_timeout=10)
    
    try:
        admin_user, admin_pass = get_domain_credentials(alias)
        conn = Connection(
            server,
            user=f'{admin_user}@{full_domain}',
            password=admin_pass,
            authentication=SIMPLE,
            auto_bind=True
        )
        return server, conn
    except Exception as e:
        raise ConnectionError(f"Failed to connect to domain controller: {str(e)}")

def get_user_ad_info(username, domain_alias):
    try:
        server, conn = get_domain_controller(domain_alias)
        full_domain = DOMAIN_MAPPINGS.get(domain_alias.lower())

        base_dn = ','.join(f'DC={part}' for part in full_domain.split('.'))
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"

        if not conn.search(
            base_dn,
            search_filter,
            search_scope='SUBTREE',
            attributes=[
                'displayName', 'sAMAccountName', 'name', 'userAccountControl',
                'pwdLastSet', 'accountExpires', 'lockoutTime',
                'userPrincipalName', 'whenChanged', 'whenCreated',
                'mail', 'department', 'distinguishedName'
            ]
        ):
            raise ValueError(f"User '{username}' not found in domain '{full_domain}'")

        if not conn.entries:
            raise ValueError(f"No results found for user '{username}'")

        user = conn.entries[0]

        def get_attribute(attr_name, default=None):
            try:
                value = getattr(user, attr_name).value
                return value if value is not None else default
            except:
                return default

        # Convert pwdLastSet
        pwd_last_set = get_attribute('pwdLastSet')
        if isinstance(pwd_last_set, (int, float)) and pwd_last_set > 0:
            pwd_last_set = datetime.fromtimestamp(pwd_last_set / 10000000 - 11644473600, UTC)
        
        # Calculate password expiration (30 days from last set)
        pwd_expiration = pwd_last_set + timedelta(days=30) if isinstance(pwd_last_set, datetime) else None

        # Handle account expiration
        account_expires = get_attribute('accountExpires')
        if isinstance(account_expires, (int, float)) and account_expires > 0:
            account_expires = datetime.fromtimestamp(account_expires / 10000000 - 11644473600, UTC)
        else:
            account_expires = None

        user_info = {
            'DisplayName': get_attribute('displayName', 'N/A'),
            'SamAccountName': get_attribute('sAMAccountName', 'N/A'),
            'Name': get_attribute('name', 'N/A'),
            'PasswordExpired': bool(int(get_attribute('userAccountControl', 0)) & 0x800000),
            'PasswordLastSet': format_datetime(pwd_last_set),
            'AccountExpirationDate': format_datetime(account_expires),
            'IsLocked': get_attribute('lockoutTime', 0) != 0,
            'IsDisabled': bool(int(get_attribute('userAccountControl', 0)) & 2),
            'UserPrincipalName': get_attribute('userPrincipalName', 'N/A'),
            'WhenChanged': format_datetime(get_attribute('whenChanged')),
            'WhenCreated': format_datetime(get_attribute('whenCreated')),
            'Mail': get_attribute('mail', 'N/A'),
            'Department': get_attribute('department', 'N/A'),
            'DistinguishedName': get_attribute('distinguishedName', 'N/A'),
            'PasswordExpirationDate': format_datetime(pwd_expiration),
        }

        # Print in PowerShell format
        max_key_length = max(len(k) for k in user_info.keys())
        for key, value in user_info.items():
            print(f"{key.ljust(max_key_length)} : {value}")

    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        if 'conn' in locals() and conn.bound:
            conn.unbind()

if __name__ == "__main__":
    try:
        username = sys.argv[1]
        domain = sys.argv[2]
        get_user_ad_info(username, domain)
    except IndexError:
        print("Usage: python AD.py <username> <domain>")
    except Exception as e:
        print(f"Error: {str(e)}")