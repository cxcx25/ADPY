import re
import ldap
from datetime import datetime, timedelta
from pytz import timezone, UTC
from ad_utils import format_datetime, get_domain_credentials, get_domain_controller, DOMAIN_MAPPINGS

def get_user_ad_info(username, domain_alias):
    try:
        ldap_conn = get_domain_controller(domain_alias)
        full_domain = DOMAIN_MAPPINGS.get(domain_alias.lower())

        base_dn = ','.join(f'DC={part}' for part in full_domain.split('.'))
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"

        ldap_conn.search_s(
            base_dn,
            ldap.SCOPE_SUBTREE,
            search_filter,
            ['displayName', 'sAMAccountName', 'name', 'userAccountControl',
             'pwdLastSet', 'accountExpires', 'lockoutTime',
             'userPrincipalName', 'whenChanged', 'whenCreated',
             'mail', 'department', 'distinguishedName']
        )

        if not ldap_conn.result_count:
            raise ValueError(f"User '{username}' not found in domain '{full_domain}'")

        user = ldap_conn.response[0]['attributes']

        def get_attribute(attr_name, default=None):
            try:
                value = user.get(attr_name, [default])[0]
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

        # Display alerts
        if user_info['PasswordExpired']:
            print("Alert: Password is expired!")
        if user_info['IsLocked']:
            print("Alert: Account is locked!")
        if user_info['IsDisabled']:
            print("Alert: Account is disabled!")
        if account_expires and account_expires < datetime.now():
            print("Alert: Account has expired!")
        if pwd_expiration and pwd_expiration < datetime.now():
            print("Alert: Password will expire soon!")

    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        if 'ldap_conn' in locals() and ldap_conn is not None:
            ldap_conn.unbind_s()
