from ad_search import search_ad_user
from ad_user_info import get_user_ad_info
import sys

def main(command, *args):
    if command == "search":
        search_ad_user(*args)
    elif command == "user-info":
        get_user_ad_info(*args)
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <command> <arguments>")
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]
    main(command, *args)
