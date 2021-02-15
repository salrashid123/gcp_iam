

## Roles/Permission Maps

Simple application to enumerate all Google Cloud `Permissions->Roles` and `Roles->Permissions` to JSON.

To use this, you must have `roles/iam.securityReviewer` role assigned to the current user or service account at the organization level.

First find the organization ID number:

```bash
$ gcloud organizations list
DISPLAY_NAME               ID  DIRECTORY_CUSTOMER_ID
esodemoapp2.com  673208786088              C023zw388
```

Then just specify that:

```bash
go run main.go -v 20 -alsologtostderr --organization 673208786088
```

The output will be a series of JSON files that list out the custom roles for at the project and organization level.

the files `roles_default.json` and `permissions_default.json` include all the roles/permissions in the organization.



```json
$ cat roles_default.json | jq '.roles[]  | select(.name=="projects/fabled-ray-104117/roles/SSHOSLoginRole")'
{
  "name": "projects/fabled-ray-104117/roles/SSHOSLoginRole",
  "role": {
    "description": "Role to grant SSH OS Login",
    "etag": "BwW6RP6hDqA=",
    "name": "projects/fabled-ray-104117/roles/SSHOSLoginRole",
    "title": "sshOSLoginRole"
  },
  "included_permissions": [
    "compute.instances.osLogin",
    "compute.instances.setMetadata",
    "compute.instances.use"
  ]
}
```

```json
$ cat permissions*.json | jq '.permissions[]  | select(.name=="compute.instances.use")'
{
  "name": "compute.instances.use",
  "roles": [
    "projects/fabled-ray-104117/roles/SSHRole",
    "projects/fabled-ray-104117/roles/SSHOSLoginRole",
    "roles/compute.instanceAdmin.v1",
    "roles/dataproc.serviceAgent",
    "roles/cloudtpu.serviceAgent",
    "roles/compute.loadBalancerAdmin",
    "roles/compute.networkAdmin",
    "roles/composer.serviceAgent",
    "roles/compute.admin",
    "roles/compute.instanceAdmin",
    "roles/container.serviceAgent",
    "roles/appengineflex.serviceAgent",
    "roles/dataflow.serviceAgent",
    "roles/cloudmigration.inframanager",
    "roles/editor",
    "roles/genomics.serviceAgent",
    "roles/lifesciences.serviceAgent",
    "roles/notebooks.legacyAdmin",
    "roles/notebooks.serviceAgent",
    "roles/owner",
    "roles/vpcaccess.serviceAgent"
  ]
}
{
  "name": "compute.instances.use",
  "roles": [
    "projects/fabled-ray-104117/roles/SSHRole",
    "projects/fabled-ray-104117/roles/SSHOSLoginRole"
  ]
}
```

### BigQuery Exports 

This script is equivalent to running an export of [GCP Policy Export to ](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy-longrunning-bigquery)
and then unnesting the included permissions.

```sql
SELECT p, r.name
 FROM `gcpdentity-asset-export-1.asset_inventory.iam_googleapis_com_Role` r, 
       UNNEST(r.resource.data.includedPermissions) p    
 WHERE DATE(timestamp) = "2021-02-12" 
```

### Cloud Console

You can use the cloud console to map the roles-permissions:

![images/permission_role.png](images/permission_role.png)

![images/role_permission.png](images/role_permission.png)
