import boto3, json

# Create an IAM client
iam = boto3.client('iam')

 # Define the administrative access policy ARN (change this if you have a custom admin policy)
administrative_policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

def get_groups_with_administrative_access():
    """
    This function lists all the IAM groups and checks if they have administrative access.

    Returns:
        A list of groups with administrative access.
    """
    # List all IAM groups
    groups_response = iam.list_groups()

    # Define a list to hold groups with admin access
    admin_groups = []

    # Check each group for administrative access
    for group in groups_response['Groups']:
        group_name = group['GroupName']
        print(f"Checking group: {group_name}")

        # Get attached policies for each group
        attached_policies_response = iam.list_attached_group_policies(GroupName=group_name)

        for policy in attached_policies_response['AttachedPolicies']:
            policy_arn = policy['PolicyArn']

            # Check if the policy grants administrative access
            if policy_arn == administrative_policy_arn:
                print(f"Group '{group_name}' has administrative access.")
                admin_groups.append(group_name)

    # List all groups with administrative access
    print("Groups with administrative access:")
    for admin_group in admin_groups:
        print(admin_group)
    return

# Function to check for administrative access in policy documents
def has_admin_permissions(policy_document):
    """
    Check if an IAM policy grants administrative access.

    Args:
        policy_document (str): The JSON-formatted IAM policy document.

    Returns:
        bool: True if the policy grants administrative access, False otherwise.

    """
    # Policy documents must be URL-decoded before they can be parsed as JSON
    policy = json.loads(policy_document)

    for statement in policy.get('Statement', []):
        # Assume a policy grants admin access if it allows all actions on all resources
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        if (statement.get('Effect', '') == 'Allow' and
                '*' in actions and
                '*' in resources):
            return True
    return False

def get_users_with_administrative_access():
    """
    This function lists all the IAM users and checks if they have administrative access.

    Returns:
        A list of users with administrative access.
    """
    # List all IAM users
    paginator = iam.get_paginator('list_users')
    admin_users = []

    # Iterate over the pages of users
    for users_response in paginator.paginate():
        for user in users_response['Users']:
            username = user['UserName']
            is_admin = False

            # Check managed policies attached to the user
            paginator = iam.get_paginator('list_attached_user_policies')
            for policy_response in paginator.paginate(UserName=username):
                for policy in policy_response['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    if policy_arn == 'arn:aws:iam::aws:policy/AdministratorAccess':
                        is_admin = True
                        break

            # Check inline policies if the user isn't already confirmed as an admin
            if not is_admin:
                paginator = iam.get_paginator('list_user_policies')
                for inline_policies_response in paginator.paginate(UserName=username):
                    for policy_name in inline_policies_response['PolicyNames']:
                        policy_version = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                        policy_document = policy_version['PolicyDocument']
                        # URL decode and check for admin permissions in the inline policy
                        if has_admin_permissions(policy_document):
                            is_admin = True
                            break

            # Check group policies if the user isn't already confirmed as an admin
            if not is_admin:
                paginator = iam.get_paginator('list_groups_for_user')
                for groups_response in paginator.paginate(UserName=username):
                    for group in groups_response['Groups']:
                        group_name = group['GroupName']

                        # Check managed policies for the group
                        paginator = iam.get_paginator('list_attached_group_policies')
                        for group_policy_response in paginator.paginate(GroupName=group_name):
                            for policy in group_policy_response['AttachedPolicies']:
                                policy_arn = policy['PolicyArn']
                                if policy_arn == 'arn:aws:iam::aws:policy/AdministratorAccess':
                                    is_admin = True
                                    break

                        # Check inline policies for the group
                        if not is_admin:
                            paginator = iam.get_paginator('list_group_policies')
                            for group_inline_policy_response in paginator.paginate(GroupName=group_name):
                                for policy_name in group_inline_policy_response['PolicyNames']:
                                    policy_version = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                                    policy_document = policy_version['PolicyDocument']
                                    # URL decode and check for admin permissions in the inline policy
                                    if has_admin_permissions(policy_document):
                                        is_admin = True
                                        break

                        if is_admin:
                            break

            if is_admin:
                admin_users.append(username)

    # Output users with administrative access
    print("Users with administrative access:")
    for admin_user in admin_users:
        print(admin_user)

if __name__ == "__main__":
    get_users_with_administrative_access()
    