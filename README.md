

Google Cloud IAM Troubleshooting scripts intended to provide several indicators of users permissions on GCP resources.

* `inspect/query` 
  - [checkEndUserPermissions](#checkEndUserPermissions)

    - Allows an end user to ask "of all the permissions this resource accepts, which ones do I have?"
    - Allows a domain administrator to _impersonate_ any user and inspect which permissions that user has on a resource.
     
  - [usePolicyTroubleshooter](#usePolicyTroubleshooter)

     - Use [IAM Policy Troubleshooter](https://cloud.google.com/iam/docs/troubleshooting-access) API to determine if the user has IAM access to a resource. 
     
     - Display if [IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview) are applicable.

     - Backtrack the [IAM Resource Hierarchy](https://cloud.google.com/iam/docs/resource-hierarchy-access-control) from the resource to root and display all the IAM Roles present at each node. (`TODO`: display subset of permissions at each node applicable to the target resource)

  - [useIAMPolicyRequest](#useIAMPolicyRequest)

    - Use [IAM Policy Analyzer](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy) to help determine if a given user has access to a resource through indirect capabilities:

      - Through nested or direct group memberships bound to the resource
      - Through [service account impersonation](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials) where the service account has direct or indirect access.
      - Other mechanisms described [here](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy#overview)

* `map/`

   The other utility provided here is basically just a forward and reverse map and graph of IAM `Roles->Permissions` and `Permissions->Roles`. Mostly just fun stuff

   See [Google Cloud IAM Roles-Permissions Public Dataset](/articles/2021/iam_bq_dataset/)
 

Note that users can have access to resources through various mechanisms and restrictions:

- User has direct IAM binding on the resource 
- User has indirect access through
  * [group membership](https://cloud.google.com/iam/docs/groups-in-cloud-console)
  * [serviceAccount Impersonation](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials)
- User has access through [Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- Access restricted through [IAM Conditions](https://cloud.google.com/iam/docs/conditions-overview)

Each of these scripts attempts to surface aspects of these access capabilities and restricts.  The intent is to use them to surface the full access scope capability for a user.

> ** This code is NOT supported by Google, really **

> NOTE: this utility is just a way to list and test Roles/Permissions.  It does not account for IAP Context-Aware access, VPC-SC or IAM Conditions


### References

- [Troubleshooting access](https://cloud.google.com/iam/docs/troubleshooting-access)
- [Analyzing IAM policies](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy)
- [Troubleshooting policy and access problems on Google Cloud](https://cloud.google.com/solutions/troubleshooting-policy-and-access-problems)
- [Representing Gsuites and Google Cloud Org structure as a Graph Database](https://github.com/salrashid123/gsuites_gcp_graphdb)