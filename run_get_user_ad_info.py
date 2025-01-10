from ad_user_info import get_user_ad_info
import sys

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_get_user_ad_info.py <username> <domain_alias>")
        sys.exit(1)

    username = sys.argv[1]
    domain_alias = sys.argv[2]
    get_user_ad_info(username, domain_alias)
