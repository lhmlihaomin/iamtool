import argparse

class AddUserResult(object):
    def __init__(self, username):
        self.username = username
        self.create_user = None
        self.create_user_msg = ""
        self.group = {}
        self.group_msg = ""
        self.password = None
        self.password_msg = ""
        self.access_key = None
        self.access_key_msg = ""

def parse_args():
    argparser = argparse.ArgumentParser(description="Manage IAM users.")
    arggroup = argparser.add_mutually_exclusive_group()
    arggroup.add_argument('-a', '--add',
                           help="Tell the script to add users",
                           action="store_true")
    arggroup.add_argument('-d', '--delete',
                           help="Tell the script to remove users",
                           action="store_true")
    argparser.add_argument('-p', '--profiles', 
                           nargs="+", 
                           help=\
"""Add/remove users from profiles listed here. "all" can be used as a
wildcard to perform action on all available profiles.""")
    argparser.add_argument('-u', '--users',
                           nargs="+",
                           help="List of usernames to be added or deleted")
    argparser.add_argument('-g', '--groups',
                           nargs="+",
                           help="Add users to these groups")
    argparser.add_argument('-P', '--create-password', help=\
"""Create password for each user when adding users. Passwords will be saved 
in output files named "<profilename>.<username>.password".
Can only be used with "-a" option.""",
                           action="store_true")
    argparser.add_argument('-A', '--create-access-key', help=\
"""Create access keys for each user when adding users. Access keys will be 
saved in output files named "<profilename>.<username>.accesskey".
Can only be used with "-a" option.""",
                           action="store_true")
    args = argparser.parse_args()
    return args


def load_profile(profile_name):
    pass


def add_users(profiles,
              usernames,
              groups=[],
              create_password=False,
              create_access_key=False):
    results = []
    for profile in profiles:
        iam_conn = connect_to_aws()
        # For each username:
        for username in usernames:
            result = AddUserResult(username)
            # Create the user:
            result.create_user, result.create_user_msg \
                = create_user(iam_conn, username)
            # Skip following steps if create user failed:
            if not result.create_user:
                continue
            # Add user to groups:
            result.group = add_user_to_groups(iam_conn, username, groups)
            # Set password: 
            result.password = create_default_password(iam_conn, username)
            # Generate access key:
            results.append(result)
    return results


def create_user(iam_conn, username):
    try:
        iam_conn.create_user(username)
        return (True, "")
    except Exception as ex:
        msg = "\n".join([ex.reason, ex.message])
        return (False, msg)


def add_user_to_groups(iam_conn, username, groups):
    result = {}
    for group in groups:
        try:
            iam_conn.add_user_to_group(group, username)
            result.update({group: True})
        except Exception as ex:
            result.update({group: False})
    return result


def default_password(username):
    pd = ""
    if len(username) < 2:
        raise Exception("Username too short")
    pd = username[0:1].upper() \
         + username[1:2].lower() \
         + username[2:] \
         + "@"
    i = 1
    while True:
        pd += str(i)
        i += 1
        if len(pd)>=12:
            break
    return pd


def create_default_password(iam_conn, username):
    password = default_password(username)
    try:
        iam_conn.create_login_profile(username, password)
        return True
    except Exception as ex:
        return False


def create_access_key(iam_conn, username):
    try:
        r = iam_conn.create_access_key(username)
    except:
        return False
    # extract useful info from that super verbose and complicated response:
    access_key = r['create_access_key_response']['create_access_key_result']\
                  ['access_key']['access_key_id']
    secret_key = r['create_access_key_response']['create_access_key_result']\
                  ['access_key']['secret_access_key']
    return (access_key, secret_key)


def delete_users(profiles,
                 users):
    pass


def main():
    args = parse_args()
    if args.add:
        print("ADD")
    if args.delete:
        print("DELETE")
    if args.profiles:
        print(args.profiles)
    if args.users:
        print(args.users)


if __name__ == "__main__":
    main()
