import logging
from ldap3 import Server, Connection, ALL, SUBTREE
try:
    from ldap3.core.exceptions import LDAPBindError
except ImportError:
    from ldap3 import LDAPBindError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from ad_utils import get_domain_credentials, get_domain_controller

def search_ad_user(name, domain="both", search_type="User", max_results=5, timeout_seconds=30):
    # Implementation of the search_ad_user() function
    pass

    logging.info(f"Searching for {search_type} with name: {name} in domain(s): {domain}")

    domains_to_search = ["el", "ess"] if domain == "both" else [domain]
    all_results_found = []

    def search_in_domain(current_domain):
        try:
            cred = get_domain_credentials(current_domain)  # Implement this function to get credentials
            dc = get_domain_controller(current_domain)  # Implement this function to get the domain controller

            logging.info(f"Searching in {current_domain} domain")

            # Domain-specific filter optimization
            if current_domain == "lux":
                filter = f"(&(objectClass=user)(|(sAMAccountName=*{name}*)(mail=*{name}*)))"
                properties = ['displayName', 'givenName', 'sn', 'mail', 'department', 'title', 'sAMAccountName']
            else:
                filter = f"(&(objectClass=user)(|(displayName=*{name}*)(sAMAccountName=*{name}*)(mail=*{name}*)))"
                properties = ['displayName', 'givenName', 'sn', 'mail', 'department', 'title']

            server = Server(dc, get_info=ALL)
            conn = Connection(server, user=cred['user'], password=cred['password'], auto_bind=True)

            # Perform the search
            conn.search(search_base='DC=example,DC=com',  # Replace with actual base DN
                        search_filter=filter,
                        attributes=properties,
                        search_scope=SUBTREE,
                        size_limit=max_results)
            return conn.entries
        except LDAPBindError as e:
            logging.error(f"Failed to bind to {current_domain} domain: {e}")
            return None
        except Exception as e:
            logging.error(f"Error searching in {current_domain} domain: {e}")
            return None

    with ThreadPoolExecutor() as executor:
        future_to_domain = {executor.submit(search_in_domain, domain): domain for domain in domains_to_search}
        start_time = time.time()
        for future in as_completed(future_to_domain):
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout_seconds:
                logging.warning(f"Search operation timed out after {timeout_seconds} seconds in {future_to_domain[future]} domain")
                continue
            results = future.result()
            if results:
                all_results_found.extend(results)

    # Process and display results
    if all_results_found:
        for result in all_results_found:
            print(f"Domain         : {result['domain']}")
            print(f"SamAccountName : {result['sAMAccountName']}")
            print(f"DisplayName    : {result['displayName']}")
            print(f"FirstName      : {result['givenName']}")
            print(f"LastName       : {result['sn']}")
            print(f"Email          : {result['mail']}")
            print(f"Department     : {result['department']}")
            print(f"Title          : {result['title']}")
            print("-" * 80)
    else:
        print(f"No {search_type} found matching '{name}'")

# Example call to the function
# search_ad_user("C22643", domain="lux", search_type="User", max_results=5, timeout_seconds=30)
