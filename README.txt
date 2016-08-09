Manage IAM users.

FEATURES
    1. AWS account profiles;
    2. Batch create users to selected profiles;
        2.1. print notification if user already exists;
        2.2. create options: password, access key
        2.3. save password/keys to files if necessary;
    3. Batch delete users from selected profiles;
        3.1. print notification if user does not exist.


USAGE
    iamtools.py [-a|--add]/[-d|--delete] \
                [-p|--profiles] profile1 profile2 profile3 \
                [-u|--users] username1 username2 username3


OPTIONS
    -a | --add
        Tell the script to add users.

    -d | --delete
        Tell the script to remove users.

    -p | --profiles
        Add/remove users from profiles listed here. "all" can be used as a
        wildcard to perform action on all available profiles.
        Profiles are stored in "<profilename>.profile.ini" files.
        Profile files must follow the format listed below:
            [global]
            ; Default region for this profile:
            region = <region_name>
            [add]
            ; Access & secret key used for adding users:
            access_key = <access_key_add>
            secret_key = <secret_key_add>
            [delete]
            ; Access & secret key used for deleting users:
            access_key = <access_key_delete>
            secret_key = <secret_key_delete>

    -u | --users
        List of usernames to be added or deleted.

    -P | --create-password
        Create password for each user when adding users. Passwords will be
        saved in output files named "<profilename>.<username>.password".
        Can only be used with "-a" option.

    -A | --create-access-key
        Create access keys for each user when adding users. Access keys will
        be saved in output files named "<profilename>.<username>.accesskey".
        Can only be used with "-a" option.

OUTPUT
    When adding users:
        Adding users:
        profile1 -- OK
        profile2 -- OK
        profile3 -- User already exists
        ...

    When deleting users:
        Deleting users:
        profile1 -- OK
        profile2 -- OK
        profile3 -- No such user
        ...

