
## GCP IAM Permissions on Resources

Utility scripts for Google Cloud IAM Permission Troubleshooting.

* `map/`:  Export all IAM `Roles->Permissions` and `Permissions->Roles`
* `query/`: Check which permissions a user has on a GCP Resource.

A sample use for the these two scripts would be as a user to deduce which permissions are lacking and on a resource and then compare the set to a predefined Role that has access.

For example, a Role `Ro1` has Permissions `[a,b,c,d]` on Resource `Re1`.   A user can issue a query on `Re1` and ask
 "give me all the permissions this resource supports"
    The response maybe `[a,b,s,t]`

At this point, you know the Role `Ro1` is overprovisioned on `Re1` since the permission delta is `[c,d]` (since those permissions would never even apply to the resource)

    
From there the user can ask 
  "which of these permissions the resource supports [a,b,s,t] do *I* have on `Re1`:
    The response maybe `[a,s]`

  If the predefined role (eg, use `map/`) or another user that can access the resource has permissions `[a,b,t]`, you would know that the permission missing maybe just `[b,t]` and `[s]` is not necessary.

This utility is primarily for information only...I'm not suggesting to go down the discrete role->permission route just yet (that would be a management nightmare quickly with out additional tools).

>> NOTE: this utility is just a way to list and test Roles/Permissions.  It does not account for IAP Context-Aware access, VPC-SC or IAM Conditions


### References

- [Troubleshooting access](https://cloud.google.com/iam/docs/troubleshooting-access)
- [Analyzing IAM policies](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy)
- [Troubleshooting policy and access problems on Google Cloud](https://cloud.google.com/solutions/troubleshooting-policy-and-access-problems)
- [Representing Gsuites and Google Cloud Org structure as a Graph Database](https://github.com/salrashid123/gsuites_gcp_graphdb)