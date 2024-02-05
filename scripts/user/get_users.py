import json
from scripts.clients import iam


def get_all_users():
    """Get all IAM users and return them as a list of dictionaries."""
    users_list = []
    marker = None

    # Paginate through the list of users if the list is long.
    while True:
        if marker:
            response = iam.list_users(Marker=marker)
        else:
            response = iam.list_users()

        for user in response['Users']:
            # Append user details (modify as needed).
            users_list.append({
                'UserName': user['UserName'],
                'UserId': user['UserId'],
                'Arn': user['Arn'],
                'CreateDate': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')
            })

        # Check if the list is truncated; set the marker to get the next set of users.
        if response['IsTruncated']:
            marker = response['Marker']
        else:
            break

    return users_list

def save_users_to_json(users, filename='aws_users.json'):
    """Save the list of users to a JSON file."""
    with open(filename, 'w') as file:
        json.dump(users, file, indent=4)

def main():
    users = get_all_users()
    save_users_to_json(users)
    print(f"Saved {len(users)} users to aws_users.json")

if __name__ == "__main__":
    main()