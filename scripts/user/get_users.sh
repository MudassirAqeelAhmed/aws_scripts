#!/bin/bash

# List all the IAM users and save the output in a variable
users=$(aws iam list-users --query "Users[].UserName" --output text)

# Iterate through each user
for user in $users; do
    # Get the policies for the current user and save the output in a variable
    policies=$(aws iam list-user-policies --user-name $user --query "PolicyNames[]" --output text)

    # Iterate through each policy and get the policy details
    for policy in $policies; do
        policy_document=$(aws iam get-user-policy --user-name $user --policy-name $policy --query "PolicyDocument" --output text)

        # Append the policy details to a text file
        echo "User: $user" >> policies.txt
        echo "Policy: $policy" >> policies.txt
        echo "Policy Document: $policy_document" >> policies.txt
        echo "" >> policies.txt
    done
done
