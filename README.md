
## GCP IAM Permissions on Resources

Utility scripts for Google Cloud IAM Permission Troubleshooting.

* `map/`:  Export all IAM `Roles->Permissions` and `Permissions->Roles`
* `query/`: Check which permissions a user has on a GCP Resource.

A sample use for the these two scripts would be as a user to deduce which permissions are lacking and on a resource and then compare the set to a predefined Role that has access.

For example, a Role `role_1` has Permissions `[a,b,c,d]` on Resource `resource_1`.   A user can issue a query on `resource_1` and ask
 "give me all the permissions this resource supports"
    The response maybe `[a,b,s,t]`

At this point, you know the Role `role_1` is overprovisioned on `resource_1` since the permission delta is `[c,d]` (since those permissions would never even apply to the resource)

    
From there the user can ask 
  "which of all permissions the resource supports do **I** have:
    The response maybe `[a,s]`

  If a predefined role or another user that can access the resource has permissions `[a,b,t]`, you would know that the permission missing maybe just `[b,t]` and `[s]` is not necessary to access that resource.


This script also provides a way to recursively determine how a user has access to a resource by traversing *BOTH* the groups hierarchy (eg, user in a group which is in another group) and the resource hierarchy (GCP organization, folder, project, resource)

>> NOTE: this utility is just a way to list and test Roles/Permissions.  It does not account for IAP Context-Aware access, VPC-SC or IAM Conditions


### References

- [Troubleshooting access](https://cloud.google.com/iam/docs/troubleshooting-access)
- [Analyzing IAM policies](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy)
- [Troubleshooting policy and access problems on Google Cloud](https://cloud.google.com/solutions/troubleshooting-policy-and-access-problems)
- [Representing Gsuites and Google Cloud Org structure as a Graph Database](https://github.com/salrashid123/gsuites_gcp_graphdb)