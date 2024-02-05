import json
from scripts.clients import iam

def perform_iam_operation(operation_callable, *args, **kwargs):
    """
    Executes an IAM operation and gracefully handles any NoSuchEntityException.
    :param operation_callable: The IAM client method to call
    """
    try:
        operation_callable(*args, **kwargs)
    except iam.exceptions.NoSuchEntityException:
        pass  # Log this if needed. Skipping for brevity.

def delete_dependencies_for_user(user_name):
    """
    Delete all dependencies associated with a user before the user can be deleted.
    """
    access_keys = iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
    for key in access_keys:
        perform_iam_operation(iam.delete_access_key, UserName=user_name, AccessKeyId=key['AccessKeyId'])

    policies = iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
    for policy in policies:
        perform_iam_operation(iam.detach_user_policy, UserName=user_name, PolicyArn=policy['PolicyArn'])

    inline_policies = iam.list_user_policies(UserName=user_name).get('PolicyNames', [])
    for policy_name in inline_policies:
        perform_iam_operation(iam.delete_user_policy, UserName=user_name, PolicyName=policy_name)

    groups = iam.list_groups_for_user(UserName=user_name).get('Groups', [])
    for group in groups:
        perform_iam_operation(iam.remove_user_from_group, UserName=user_name, GroupName=group['GroupName'])

    certs = iam.list_signing_certificates(UserName=user_name).get('Certificates', [])
    for cert in certs:
        perform_iam_operation(iam.delete_signing_certificate, UserName=user_name, CertificateId=cert['CertificateId'])

    ssh_keys = iam.list_ssh_public_keys(UserName=user_name).get('SSHPublicKeys', [])
    for key in ssh_keys:
        perform_iam_operation(iam.delete_ssh_public_key, UserName=user_name, SSHPublicKeyId=key['SSHPublicKeyId'])

    creds = iam.list_service_specific_credentials(UserName=user_name).get('ServiceSpecificCredentials', [])
    for cred in creds:
        perform_iam_operation(iam.delete_service_specific_credential, UserName=user_name, ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId'])

    perform_iam_operation(iam.delete_login_profile, UserName=user_name)

    # Finally, attempt to delete the user
    perform_iam_operation(iam.delete_user, UserName=user_name)

def delete_users_from_json(except_users, json_file='aws_users.json'):
    """
    Delete users based on a JSON file, excluding specified usernames.
    """
    with open(json_file, 'r') as file:
        users = json.load(file)

    for user in users:
        user_name = user['UserName']
        try:
            # An example IAM operation
            iam.get_user(UserName=user_name)
        except iam.exceptions.NoSuchEntityException:
            # Handle the error
            print("User does not exist.")
            continue
        if user_name not in except_users:
            print(f"Deleting user: {user_name}")
            delete_dependencies_for_user(user_name)
            print(f"User {user_name} deleted successfully.")
        else:
            print(f"User {user_name} is in the exception list and will not be deleted.")

def main():
    # Define a list of usernames that should not be deleted
    EXCEPT_USERS = ['user1', 'user2', 'user3']
    
    delete_users_from_json(EXCEPT_USERS)

if __name__ == "__main__":
    main()