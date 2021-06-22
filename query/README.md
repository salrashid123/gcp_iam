
## IAM Permission Verification


Utility functions for IAM Permissions troubleshooting:

- `A` As a user, which permissions do _i_ have on a resource
  In other words, if a Resource can potentially have permissions `[A,B,C,E,F,G]`, this script will enumerate those as list which of those permissions the current user has (eg, maybe just `[B,F,G]`.  For example "of all the potential IAM roles on a GCS bucket, alice has `storage.objects.get`"

- `B` As an admin, which permissions and roles does a user have on a resource using [Asset Inventory API](https://cloud.google.com/asset-inventory/docs/apis)
  An admin needs to know both the identity/group part of the iam binding and where in the resource hierarchy the grant was committed.  For example, if a user is a member of a group with is member of another group that has an IAM role granted at a project level, this script will trace back the hierarchy on both the [resource grant path](https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy) and the one derived from being nested within groups.  eg:

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   \
   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117" \
    -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117

I0614 07:15:07.776025 2063876 main.go:116] Getting AnalyzeIamPolicyRequest
I0614 07:15:08.587882 2063876 main.go:164]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0614 07:15:08.588146 2063876 main.go:165]         through role [permission:"storage.objects.get" role:"roles/storage.objectViewer" permission:"storage.objects.list"]
I0614 07:15:08.588360 2063876 main.go:169]           which is applied to the resource directly
I0614 07:15:08.588533 2063876 main.go:178]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com   --> group:group_of_groups_1@esodemoapp2.com 
```

This utility also uses [Policy Troubleshooter](https://cloud.google.com/iam/docs/troubleshooting-access) API to help derive the set of permissions that granted or denied access. However, that API is quite difficult to understand so I approached deriving the data for `B` using `analyzeIamPolicy` api instead.


- `C` As an admin, determine if a user has accesss to a resource using the [PolicyTroubleshooter API](https://cloud.google.com/iam/docs/reference/policytroubleshooter/rest) to help answer question `B`.
   However, it does not seem to elaborate on the group hierarchy nor the IAM resource hierarchy

```log
 go run main.go   --checkResource="//storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket"   --identity="user4@esodemoapp2.com"  \
   --usePolicyTroubleshooter --permissionToCheck=storage.objects.get --projectID fabled-ray-104117    -v 20 -alsologtostderr 

I0613 14:24:31.180394 1974747 main.go:183] Getting PolicyTroubleshooter
I0613 14:24:32.138580 1974747 main.go:215]    User's AccessState GRANTED
I0613 14:24:32.138751 1974747 main.go:219]    User's AccessState granted at //cloudresourcemanager.googleapis.com/projects/fabled-ray-104117
I0613 14:24:32.142876 1974747 main.go:225]    within which the user has binding with permission via roles roles/storage.objectViewer
I0613 14:24:32.142984 1974747 main.go:226]    through membership map[group:group_of_groups_1@esodemoapp2.com:membership:MEMBERSHIP_INCLUDED  relevance:HIGH]
```

as of 5/14/21, the script is geared towards why a user _does_ have access vs why the identity does not.

the larger question is...which apis should i use? IMO, the AssetAPI provides a more robust map of the permissions and allows you to recurse serviceAccount impersonation in offline mode as well.

Do not use APIs `B` or `C` for live serving path IAM validation:  these are just too slow and intended for administration and backend offline checks.

---

>> This repo is NOT supported by google and is very experimental.  Do not use in production.

---

References:

- [Testing Permissions](https://cloud.google.com/iam/docs/testing-permissions)
- [QueryTestablePermissions](https://pkg.go.dev/google.golang.org/api/iam/v1#PermissionsService.QueryTestablePermissions)
- [Troubleshooting access using Policy Troubleshooter](https://cloud.google.com/iam/docs/troubleshooting-access)
- [Testable IAM Resource Names](https://cloud.google.com/iam/docs/full-resource-names)
- [Analyzing IAM Policy](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy)
- [analyzeIamPolicy](https://cloud.google.com/asset-inventory/docs/reference/rest/v1p4beta1/TopLevel/analyzeIamPolicy)
- [IamPolicyAnalysisQuery Advanced Options](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/IamPolicyAnalysisQuery#options)
- [Determining what access a principal has on a resource](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy#access-query)

---

Provided utility accepts the following parameters

| Option | Description |
|:------------|-------------|
| **`checkResource`** | `string` The canonical resource name to verify |
| **`identity`** | `string` The user or serviceAccount to verify |
| **`scope`** | `string` Scanning scope (`projects/projectID`,`organization/organizationNumber`)|
| **`useIAMPolicyRequest`** | `bool` Invoke `AnalyzeIamPolicyRequest` on the resource and user (`default: false`) |
| **`usePolicyTroubleshooter`** | `bool` Invoke ` IAM Policy Troubleshooter api` on the resource and user (`default: false`) |
| **`gcsDestinationForLongRunningAnalysis`** | `string` GCS bucket where longrunning IAM impersonation checks are stored (in format `gs://bucket`) |

If run with high verbosity (`-v 20 -alsologtostderr`) output of the script, the current applicable permissions are listed and after that, each of those are tested against the resource.  Any permission that succeeds will be shown below the segment `User permission  on resource:`

---

## A: Which Permissions do I have

The sample here can evaluate the following resource types

- [BigQuery Tables](#bigquery-tables)
- [Service Account](#service-accounts)
- [Service Account Keys](#service-account-keys)
- [IAP AppEngine](#iap-appengine)
- [IAP GCE](#iap-gce)
- [Spanner](#spanner)
- [GCS](#gcs)
- [GCE](#gce)
- [Compute Engine Networks](#compute-engine-networks)
- [Compute Engine SubNetworks](#compute-engine-subNetworks)
- [Kubernetes Engine](#kubernetes-engine)
- [Organization](#organization)
- [Project](#project)

GCP accepts many other resource that can be verified (just look for resources that have [`TestIAMPermission()`](https://pkg.go.dev/google.golang.org/api/iam/v1#TestIamPermissionsRequest) api enabled)



### BigQuery Tables

```bash
$ go run main.go \
  --checkResource="//bigquery.googleapis.com/projects/fabled-ray-104117/datasets/test/tables/person" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

    I0214 14:36:06.895239  399827 main.go:74] ================ QueryTestablePermissions with Resource ======================
    I0214 14:36:08.551446  399827 main.go:90] Testable permissions on resource :
    I0214 14:36:08.551504  399827 main.go:92]      bigquery.tables.delete
    I0214 14:36:08.551532  399827 main.go:92]      bigquery.tables.export
    I0214 14:36:08.551558  399827 main.go:92]      bigquery.tables.get
    I0214 14:36:08.551579  399827 main.go:92]      bigquery.tables.getData
    I0214 14:36:08.551600  399827 main.go:92]      bigquery.tables.getIamPolicy
    I0214 14:36:08.551622  399827 main.go:92]      bigquery.tables.setCategory
    I0214 14:36:08.551644  399827 main.go:92]      bigquery.tables.setIamPolicy
    I0214 14:36:08.551664  399827 main.go:92]      bigquery.tables.update
    I0214 14:36:08.551683  399827 main.go:92]      bigquery.tables.updateData
    I0214 14:36:08.551710  399827 main.go:92]      bigquery.tables.updateTag
    I0214 14:36:08.551737  399827 main.go:98] ==== TestIAMPermissions ====
    I0214 14:36:08.551916  399827 main.go:106] ==== TestIAMPermissions as BigQuery Tables Resource ====
    I0214 14:36:08.943417  399827 main.go:126]  User permission  on resource: 
    I0214 14:36:08.943596  399827 main.go:128]      bigquery.tables.export
    I0214 14:36:08.943648  399827 main.go:128]      bigquery.tables.get
    I0214 14:36:08.943690  399827 main.go:128]      bigquery.tables.getData
    I0214 14:36:08.943730  399827 main.go:128]      bigquery.tables.getIamPolicy
```

### Service Accounts

The following shows the output if the user has
 `ServiceAccount User` permission only:

```bash
$ go run main.go \
  --checkResource="//iam.googleapis.com/projects/fabled-ray-104117/serviceAccounts/kms-svc-account@fabled-ray-104117.iam.gserviceaccount.com" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

  I0214 15:44:37.250096  415043 main.go:74] ================ QueryTestablePermissions with Resource ======================
  I0214 15:44:37.826276  415043 main.go:90] Testable permissions on resource :
  I0214 15:44:37.826344  415043 main.go:92]      iam.serviceAccountKeys.create
  I0214 15:44:37.826373  415043 main.go:92]      iam.serviceAccountKeys.delete
  I0214 15:44:37.826423  415043 main.go:92]      iam.serviceAccountKeys.get
  I0214 15:44:37.826448  415043 main.go:92]      iam.serviceAccountKeys.list
  I0214 15:44:37.826469  415043 main.go:92]      iam.serviceAccounts.actAs
  I0214 15:44:37.826494  415043 main.go:92]      iam.serviceAccounts.delete
  I0214 15:44:37.826517  415043 main.go:92]      iam.serviceAccounts.disable
  I0214 15:44:37.826539  415043 main.go:92]      iam.serviceAccounts.enable
  I0214 15:44:37.826562  415043 main.go:92]      iam.serviceAccounts.get
  I0214 15:44:37.826585  415043 main.go:92]      iam.serviceAccounts.getAccessToken
  I0214 15:44:37.826607  415043 main.go:92]      iam.serviceAccounts.getIamPolicy
  I0214 15:44:37.826628  415043 main.go:92]      iam.serviceAccounts.getOpenIdToken
  I0214 15:44:37.826647  415043 main.go:92]      iam.serviceAccounts.implicitDelegation
  I0214 15:44:37.826670  415043 main.go:92]      iam.serviceAccounts.setIamPolicy
  I0214 15:44:37.826693  415043 main.go:92]      iam.serviceAccounts.signBlob
  I0214 15:44:37.826713  415043 main.go:92]      iam.serviceAccounts.signJwt
  I0214 15:44:37.826733  415043 main.go:92]      iam.serviceAccounts.undelete
  I0214 15:44:37.826762  415043 main.go:92]      iam.serviceAccounts.update
  I0214 15:44:37.827129  415043 main.go:136] ==== TestIAMPermissions as ServiceAccounts Resource ====
  I0214 15:44:38.133249  415043 main.go:156]  User permission  on resource: 
  I0214 15:44:38.133341  415043 main.go:158]      iam.serviceAccounts.actAs
  I0214 15:44:38.133389  415043 main.go:158]      iam.serviceAccounts.get

```

or  `ServiceAccount TokenCreator`

```bash
$ go run main.go \
  --checkResource="//iam.googleapis.com/projects/fabled-ray-104117/serviceAccounts/kms-svc-account@fabled-ray-104117.iam.gserviceaccount.com" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

  I0214 15:45:35.273730  415231 main.go:74] ================ QueryTestablePermissions with Resource ======================
  I0214 15:45:35.784151  415231 main.go:90] Testable permissions on resource :
  I0214 15:45:35.784219  415231 main.go:92]      iam.serviceAccountKeys.create
  I0214 15:45:35.784250  415231 main.go:92]      iam.serviceAccountKeys.delete
  I0214 15:45:35.784272  415231 main.go:92]      iam.serviceAccountKeys.get
  I0214 15:45:35.784292  415231 main.go:92]      iam.serviceAccountKeys.list
  I0214 15:45:35.784313  415231 main.go:92]      iam.serviceAccounts.actAs
  I0214 15:45:35.784334  415231 main.go:92]      iam.serviceAccounts.delete
  I0214 15:45:35.784353  415231 main.go:92]      iam.serviceAccounts.disable
  I0214 15:45:35.784373  415231 main.go:92]      iam.serviceAccounts.enable
  I0214 15:45:35.784395  415231 main.go:92]      iam.serviceAccounts.get
  I0214 15:45:35.784416  415231 main.go:92]      iam.serviceAccounts.getAccessToken
  I0214 15:45:35.784435  415231 main.go:92]      iam.serviceAccounts.getIamPolicy
  I0214 15:45:35.784458  415231 main.go:92]      iam.serviceAccounts.getOpenIdToken
  I0214 15:45:35.784480  415231 main.go:92]      iam.serviceAccounts.implicitDelegation
  I0214 15:45:35.784498  415231 main.go:92]      iam.serviceAccounts.setIamPolicy
  I0214 15:45:35.784516  415231 main.go:92]      iam.serviceAccounts.signBlob
  I0214 15:45:35.784536  415231 main.go:92]      iam.serviceAccounts.signJwt
  I0214 15:45:35.784558  415231 main.go:92]      iam.serviceAccounts.undelete
  I0214 15:45:35.784581  415231 main.go:92]      iam.serviceAccounts.update
  I0214 15:45:35.784822  415231 main.go:136] ==== TestIAMPermissions as ServiceAccounts Resource ====
  I0214 15:45:36.091325  415231 main.go:156]  User permission  on resource: 
  I0214 15:45:36.091403  415231 main.go:158]      iam.serviceAccounts.actAs
  I0214 15:45:36.091449  415231 main.go:158]      iam.serviceAccounts.get
  I0214 15:45:36.091489  415231 main.go:158]      iam.serviceAccounts.getAccessToken
  I0214 15:45:36.091530  415231 main.go:158]      iam.serviceAccounts.getOpenIdToken
  I0214 15:45:36.091568  415231 main.go:158]      iam.serviceAccounts.implicitDelegation
  I0214 15:45:36.091607  415231 main.go:158]      iam.serviceAccounts.signBlob
  I0214 15:45:36.091645  415231 main.go:158]      iam.serviceAccounts.signJwt
```

### Service Account Keys

>> Unimplemented

TestIAMPermissions does not exist with [ServiceAccountKeys](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys)


The documentation links above mention support but so far i do not think this capability applies to keys.  If it did, i suspect the API would look like
```bash
go run main.go \
  --checkResource="//iam.googleapis.com/projects/fabled-ray-104117/serviceAccounts/kms-svc-account@fabled-ray-104117.iam.gserviceaccount.com/keys/4d7bbaf8369e2219b657e9e09cf9d2ec785376a9" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr
```

### IAP AppEngine


>> Note: use the _Project Number_  (not ID) in the ResourceURL

```bash
$ go run main.go \
  --checkResource="//iap.googleapis.com/projects/248066739582/iap_web/appengine-fabled-ray-104117/services/default" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

  I0214 16:40:33.275636  425038 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 16:40:33.751844  425038 main.go:91] Testable permissions on resource :
  I0214 16:40:33.751916  425038 main.go:93]      iap.webServiceVersions.accessViaIAP
  I0214 16:40:33.751943  425038 main.go:93]      iap.webServiceVersions.getIamPolicy
  I0214 16:40:33.751963  425038 main.go:93]      iap.webServiceVersions.getSettings
  I0214 16:40:33.751983  425038 main.go:93]      iap.webServiceVersions.setIamPolicy
  I0214 16:40:33.752011  425038 main.go:93]      iap.webServiceVersions.updateSettings
  I0214 16:40:33.752030  425038 main.go:93]      iap.webServices.getIamPolicy
  I0214 16:40:33.752049  425038 main.go:93]      iap.webServices.getSettings
  I0214 16:40:33.752067  425038 main.go:93]      iap.webServices.setIamPolicy
  I0214 16:40:33.752085  425038 main.go:93]      iap.webServices.updateSettings
  I0214 16:40:33.752375  425038 main.go:198] ==== TestIAMPermissions as IAP AppEngine Resource ====
  I0214 16:40:34.161528  425038 main.go:218]  User permission  on resource: 
  I0214 16:40:34.161614  425038 main.go:220]      iap.webServiceVersions.accessViaIAP

```

### IAP GCE

>> Note: use the the *NUMBER* for the GCE Backend Service  (not ID) in the ResourceURL as well as the Project Number

```bash
$ go run main.go \
  --checkResource="//iap.googleapis.com/projects/248066739582/iap_web/compute/services/1860257571542433058" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

  I0214 20:19:20.692131  459219 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 20:19:21.144688  459219 main.go:91] Testable permissions on resource :
  I0214 20:19:21.144744  459219 main.go:93]      iap.webServiceVersions.accessViaIAP
  I0214 20:19:21.144770  459219 main.go:93]      iap.webServiceVersions.getIamPolicy
  I0214 20:19:21.144789  459219 main.go:93]      iap.webServiceVersions.getSettings
  I0214 20:19:21.144813  459219 main.go:93]      iap.webServiceVersions.setIamPolicy
  I0214 20:19:21.144831  459219 main.go:93]      iap.webServiceVersions.updateSettings
  I0214 20:19:21.144851  459219 main.go:93]      iap.webServices.getIamPolicy
  I0214 20:19:21.144865  459219 main.go:93]      iap.webServices.getSettings
  I0214 20:19:21.144880  459219 main.go:93]      iap.webServices.setIamPolicy
  I0214 20:19:21.144895  459219 main.go:93]      iap.webServices.updateSettings
  I0214 20:19:21.145300  459219 main.go:231] ==== TestIAMPermissions as IAP ComputeEngine Resource ====
  I0214 20:19:21.520106  459219 main.go:251]  User permission  on resource: 
  I0214 20:19:21.520189  459219 main.go:253]      iap.webServiceVersions.accessViaIAP
```

### Spanner

```bash
$ go run main.go \
  --checkResource="//spanner.googleapis.com/projects/fabled-ray-104117/instances/spanner-1" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

  I0214 20:29:48.719984  460579 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 20:29:49.227735  460579 main.go:91] Testable permissions on resource :
  I0214 20:29:49.227796  460579 main.go:93]      spanner.backupOperations.cancel
  I0214 20:29:49.227821  460579 main.go:93]      spanner.backupOperations.get
  I0214 20:29:49.227840  460579 main.go:93]      spanner.backupOperations.list
  I0214 20:29:49.227858  460579 main.go:93]      spanner.backups.create
  I0214 20:29:49.227876  460579 main.go:93]      spanner.backups.delete
  ...
  ...
  I0214 20:29:49.228555  460579 main.go:93]      spanner.instances.delete
  I0214 20:29:49.228576  460579 main.go:93]      spanner.instances.get
  I0214 20:29:49.228597  460579 main.go:93]      spanner.instances.getIamPolicy
  I0214 20:29:49.228618  460579 main.go:93]      spanner.instances.setIamPolicy
  I0214 20:29:49.228637  460579 main.go:93]      spanner.instances.update
  I0214 20:29:49.228658  460579 main.go:93]      spanner.sessions.create
  I0214 20:29:49.228682  460579 main.go:93]      spanner.sessions.delete
  I0214 20:29:49.228714  460579 main.go:93]      spanner.sessions.get
  I0214 20:29:49.228743  460579 main.go:93]      spanner.sessions.list
  I0214 20:29:49.229119  460579 main.go:262] ==== TestIAMPermissions as Spanner Resource ====
  I0214 20:29:49.545857  460579 main.go:282]  User permission  on resource: 
  I0214 20:29:49.545951  460579 main.go:284]      spanner.databaseOperations.cancel
  I0214 20:29:49.546005  460579 main.go:284]      spanner.databaseOperations.delete
  I0214 20:29:49.546051  460579 main.go:284]      spanner.databaseOperations.get
  I0214 20:29:49.546097  460579 main.go:284]      spanner.databaseOperations.list
  I0214 20:29:49.546143  460579 main.go:284]      spanner.databases.beginOrRollbackReadWriteTransaction
  I0214 20:29:49.546189  460579 main.go:284]      spanner.databases.beginPartitionedDmlTransaction
  I0214 20:29:49.546234  460579 main.go:284]      spanner.databases.beginReadOnlyTransaction
  I0214 20:29:49.546280  460579 main.go:284]      spanner.databases.getDdl
  I0214 20:29:49.546326  460579 main.go:284]      spanner.databases.partitionQuery
  I0214 20:29:49.546370  460579 main.go:284]      spanner.databases.partitionRead
  I0214 20:29:49.546418  460579 main.go:284]      spanner.databases.read
  I0214 20:29:49.546464  460579 main.go:284]      spanner.databases.select
  I0214 20:29:49.546536  460579 main.go:284]      spanner.databases.updateDdl
  I0214 20:29:49.546590  460579 main.go:284]      spanner.databases.write
  I0214 20:29:49.546639  460579 main.go:284]      spanner.instances.get
  I0214 20:29:49.546690  460579 main.go:284]      spanner.sessions.create
  I0214 20:29:49.546735  460579 main.go:284]      spanner.sessions.delete
  I0214 20:29:49.546780  460579 main.go:284]      spanner.sessions.get
  I0214 20:29:49.546829  460579 main.go:284]      spanner.sessions.list
```

>> TODO:: verify if its possible to testIAM permissions on the Spanner Database and DatabaseBackup too (it should be possible)

- [ProjectsInstancesDatabasesTestIamPermissionsCall](https://pkg.go.dev/google.golang.org/api@v0.40.0/spanner/v1#ProjectsInstancesDatabasesTestIamPermissionsCall)
- [ProjectsInstancesBackupsSetIamPolicyCall](https://pkg.go.dev/google.golang.org/api@v0.40.0/spanner/v1#ProjectsInstancesBackupsService.TestIamPermissions)

### GCS

```bash
$ go run main.go \
  --checkResource="//storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr

    I0214 14:17:25.687252  397623 main.go:73] ================ QueryTestablePermissions with Resource ======================
    I0214 14:17:26.158213  397623 main.go:89] Testable permissions on resource :
    I0214 14:17:26.158273  397623 main.go:91]      resourcemanager.resourceTagBindings.create
    I0214 14:17:26.158300  397623 main.go:91]      resourcemanager.resourceTagBindings.delete
    I0214 14:17:26.158320  397623 main.go:91]      resourcemanager.resourceTagBindings.list
    I0214 14:17:26.158339  397623 main.go:91]      storage.buckets.delete
    I0214 14:17:26.158358  397623 main.go:91]      storage.buckets.get
    I0214 14:17:26.158379  397623 main.go:91]      storage.buckets.getIamPolicy
    I0214 14:17:26.158427  397623 main.go:91]      storage.buckets.setIamPolicy
    I0214 14:17:26.158448  397623 main.go:91]      storage.buckets.update
    I0214 14:17:26.158466  397623 main.go:91]      storage.objects.create
    I0214 14:17:26.158490  397623 main.go:91]      storage.objects.delete
    I0214 14:17:26.158509  397623 main.go:91]      storage.objects.get
    I0214 14:17:26.158527  397623 main.go:91]      storage.objects.getIamPolicy
    I0214 14:17:26.158545  397623 main.go:91]      storage.objects.list
    I0214 14:17:26.158562  397623 main.go:91]      storage.objects.setIamPolicy
    I0214 14:17:26.158580  397623 main.go:91]      storage.objects.update
    I0214 14:17:26.158602  397623 main.go:95] ==== TestIAMPermissions ====
    I0214 14:17:26.158851  397623 main.go:142] ==== TestIAMPermissions as GCS Bucket Resource ====
    I0214 14:17:26.660470  397623 main.go:163]  User permission  on resource: 
    I0214 14:17:26.660537  397623 main.go:165]      storage.objects.get
    I0214 14:17:26.660570  397623 main.go:165]      storage.objects.list
```

Note:  for GCS, the resource name cited there is [compatible with IAM](https://cloud.google.com/iam/docs/full-resource-names) but the response resource name could be different (eg, GCS may return a resource name as `//storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket` as `//storage.googleapis.com/fabled-ray-104117-bucket` )

### GCE Instance

```bash
go run main.go --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/zones/us-central1-a/instances/external"  \
      --scope="projects/fabled-ray-104117" \
      -v 20 -alsologtostderr

  I0214 16:42:03.139289  425260 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 16:42:03.637405  425260 main.go:91] Testable permissions on resource :
  I0214 16:42:03.637486  425260 main.go:93]      compute.instances.addAccessConfig
  I0214 16:42:03.637516  425260 main.go:93]      compute.instances.addMaintenancePolicies
  I0214 16:42:03.637537  425260 main.go:93]      compute.instances.attachDisk
  I0214 16:42:03.637558  425260 main.go:93]      compute.instances.delete
  I0214 16:42:03.637583  425260 main.go:93]      compute.instances.deleteAccessConfig
  I0214 16:42:03.637602  425260 main.go:93]      compute.instances.detachDisk
  I0214 16:42:03.637620  425260 main.go:93]      compute.instances.get
  ...
  ...
  I0214 16:42:03.638292  425260 main.go:93]      compute.instances.updateShieldedVmConfig
  I0214 16:42:03.638310  425260 main.go:93]      compute.instances.use
  I0214 16:42:03.638328  425260 main.go:93]      compute.instances.useReadOnly
  I0214 16:42:03.638345  425260 main.go:93]      resourcemanager.resourceTagBindings.create
  I0214 16:42:03.638363  425260 main.go:93]      resourcemanager.resourceTagBindings.delete
  I0214 16:42:03.638379  425260 main.go:93]      resourcemanager.resourceTagBindings.list
  I0214 16:42:03.638729  425260 main.go:230] ==== TestIAMPermissions as Compute Instance Resource ====
  I0214 16:42:03.965579  425260 main.go:251]  User permission  on resource: 
  I0214 16:42:03.965656  425260 main.go:253]      compute.instances.get
  I0214 16:42:03.965695  425260 main.go:253]      compute.instances.getEffectiveFirewalls
  I0214 16:42:03.965732  425260 main.go:253]      compute.instances.getGuestAttributes
  I0214 16:42:03.965767  425260 main.go:253]      compute.instances.getIamPolicy
  I0214 16:42:03.965801  425260 main.go:253]      compute.instances.getScreenshot
  I0214 16:42:03.965839  425260 main.go:253]      compute.instances.getSerialPortOutput
  I0214 16:42:03.965875  425260 main.go:253]      compute.instances.getShieldedInstanceIdentity
  I0214 16:42:03.965950  425260 main.go:253]      compute.instances.getShieldedVmIdentity
  I0214 16:42:03.965986  425260 main.go:253]      compute.instances.listReferrers
```

### Compute Engine Networks

>> Unimplemented

TestIAMPermissions does not exist with [ComputeEngine Networks](https://cloud.google.com/compute/docs/reference/rest/v1/networks)


```bash
go run main.go --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/global/networks/default"  \
      --scope="projects/fabled-ray-104117" \
      -v 20 -alsologtostderr
```

### Compute Engine SubNetworks
	
```bash
go run main.go --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/regions/us-central1/subnetworks/default"  \
      --scope="projects/fabled-ray-104117" \
      -v 20 -alsologtostderr

  I0214 21:08:30.983880  468031 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 21:08:31.625494  468031 main.go:91] Testable permissions on resource :
  I0214 21:08:31.625568  468031 main.go:93]      compute.subnetworks.delete
  I0214 21:08:31.625617  468031 main.go:93]      compute.subnetworks.expandIpCidrRange
  I0214 21:08:31.625640  468031 main.go:93]      compute.subnetworks.get
  I0214 21:08:31.625661  468031 main.go:93]      compute.subnetworks.getIamPolicy
  I0214 21:08:31.625680  468031 main.go:93]      compute.subnetworks.mirror
  I0214 21:08:31.625700  468031 main.go:93]      compute.subnetworks.setIamPolicy
  I0214 21:08:31.625720  468031 main.go:93]      compute.subnetworks.setPrivateIpGoogleAccess
  I0214 21:08:31.625741  468031 main.go:93]      compute.subnetworks.update
  I0214 21:08:31.625760  468031 main.go:93]      compute.subnetworks.use
  I0214 21:08:31.625780  468031 main.go:93]      compute.subnetworks.useExternalIp
  I0214 21:08:32.234384  468031 main.go:422]  User permission  on resource: 
  I0214 21:08:32.234450  468031 main.go:424]      compute.subnetworks.get
  I0214 21:08:32.234484  468031 main.go:424]      compute.subnetworks.getIamPolicy
```

Note, verifying permissions requires atleast parent `compute.subnetworks.list` permission on project

### Kubernetes Engine

>> Unimplemented

TestIAMPermissions does not exist with [Kubernetes Engine Cluster](https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters)

	
```bash
go run main.go --checkResource="//container.googleapis.com/projects/fabled-ray-104117/clusters/cluster-1"  \
      --scope="projects/fabled-ray-104117" \
      -v 20 -alsologtostderr

  I0214 21:08:30.983880  468031 main.go:75] ================ QueryTestablePermissions with Resource ======================
  I0214 21:08:31.625494  468031 main.go:91] Testable permissions on resource :
  I0214 21:08:31.625568  468031 main.go:93]      compute.subnetworks.delete
  I0214 21:08:31.625617  468031 main.go:93]      compute.subnetworks.expandIpCidrRange
  I0214 21:08:31.625640  468031 main.go:93]      compute.subnetworks.get
  I0214 21:08:31.625661  468031 main.go:93]      compute.subnetworks.getIamPolicy
  I0214 21:08:31.625680  468031 main.go:93]      compute.subnetworks.mirror
  I0214 21:08:31.625700  468031 main.go:93]      compute.subnetworks.setIamPolicy
  I0214 21:08:31.625720  468031 main.go:93]      compute.subnetworks.setPrivateIpGoogleAccess
  I0214 21:08:31.625741  468031 main.go:93]      compute.subnetworks.update
  I0214 21:08:31.625760  468031 main.go:93]      compute.subnetworks.use
  I0214 21:08:31.625780  468031 main.go:93]      compute.subnetworks.useExternalIp
  I0214 21:08:32.234384  468031 main.go:422]  User permission  on resource: 
  I0214 21:08:32.234450  468031 main.go:424]      compute.subnetworks.get
  I0214 21:08:32.234484  468031 main.go:424]      compute.subnetworks.getIamPolicy
```

### Organization

Assume the current user has org-level IAM permissions
	
```bash
go run main.go --checkResource="//cloudresourcemanager.googleapis.com/organizations/673208786098"  \
      --scope="organization/673208786098" \
      -v 20 -alsologtostderr

  I0214 22:13:53.119180  478584 main.go:77] ================ QueryTestablePermissions with Resource ======================
  I0214 22:13:53.824738  478584 main.go:104] ================ Getting Permissions CgoHBbtXYC7U5CABEM2Sqe_h8NrPDhhkIiphaXBsYXRmb3JtLmh5cGVycGFyYW1ldGVyVHVuaW5nSm9icy5kZWxldGU
  I0214 22:13:53.824811  478584 main.go:107]             Adding Permission to check accessapproval.requests.approve
  I0214 22:13:53.824840  478584 main.go:107]             Adding Permission to check accessapproval.requests.dismiss
  I0214 22:13:53.824858  478584 main.go:107]             Adding Permission to check accessapproval.requests.get
  I0214 22:13:53.824882  478584 main.go:107]             Adding Permission to check accessapproval.requests.list
  I0214 22:13:53.824902  478584 main.go:107]             Adding Permission to check accessapproval.settings.delete
  ...
  ...
  I0214 22:14:10.884707  478584 main.go:120]      workflows.workflows.list
  I0214 22:14:10.884713  478584 main.go:120]      workflows.workflows.setIamPolicy
  I0214 22:14:10.884718  478584 main.go:120]      workflows.workflows.update

  I0214 22:14:10.884903  478584 main.go:495] ==== TestIAMPermissions on Organizations ====
  I0214 22:14:10.885015  478584 main.go:519]  User permission  on resource: 
  I0214 22:14:13.177049  478584 main.go:535]      clientauthconfig.brands.get
  I0214 22:14:13.177125  478584 main.go:535]      clientauthconfig.brands.list
```

### Project

In the example below, the user has a customer role (custom in this case) with just `iap.tunnelInstances.accessViaIAP`

```bash
$ go run main.go --checkResource="//cloudresourcemanager.googleapis.com/projects/fabled-ray-104117"   \
    --scope="projects/fabled-ray-104117" \
    -v 10 -alsologtostderr
  I0214 22:27:19.213100  480876 main.go:77] ================ QueryTestablePermissions with Resource ======================
  I0214 22:27:40.903787  480876 main.go:118] Testable permissions on resource :
  I0214 22:27:40.903845  480876 main.go:120]      accessapproval.requests.approve



  I0214 22:27:40.990615  480876 main.go:120]      workflows.workflows.update
  I0214 22:27:40.990784  480876 main.go:546] ==== TestIAMPermissions on Project ====
  I0214 22:27:40.990882  480876 main.go:570]  User permission  on resource: 
  I0214 22:27:42.746844  480876 main.go:586]      clientauthconfig.brands.get
  I0214 22:27:42.746924  480876 main.go:586]      clientauthconfig.brands.list
  I0214 22:27:49.709987  480876 main.go:586]      iap.tunnelInstances.accessViaIAP
```

---

## B: Which Permissions and Roles does a user have on a resource

Analyzes IAM policies to answer which identities have what accesses on which resources.  

This flag is intended to be used only by a domain Administrator to check which policies are in effect for a given user.  It is NOT intended to be used by a user checking if he/she has access to a resource.

Sample output when run by an administrator would show the resource and IAM Role the specified user (`user4@esodemoapp2.com`) has 

NOTE, the examples below uses GCS which accepts two [resource name formats](https://cloud.google.com/iam/docs/full-resource-names):

* `//storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket`:  This is the canonical format 
* `//storage.googleapis.com/fabled-ray-104117-bucket`: This is the format that GCS responds back with.

We will be using the second, non-compliant format since the code checks the provided response value formats

The code first attempts to use `AnalyzeIamPolicy` to acquire the map. If the MainAnalysis is `FullyExplored`, then we will render the map as-is.  If not, the program will run `AnalyzeIamPolicyLongrunningRequest` and save the output to a GCS bucket `gcsDestinationForLongRunningAnalysis`.  Note you must create this GCS bucket first and then have permissions to read and write to it.  For more information, see

* [Writing policy analysis to Cloud Storage](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy-longrunning-cloud-storage)

- `A` user does not have access

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:32:12.288088 1965268 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:32:12.772178 1965268 main.go:173]       user:user4@esodemoapp2.com does not access to resource //storage.googleapis.com/fabled-ray-104117-bucket
```

- `B` user has direct access to resource

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:33:27.323535 1965409 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:33:27.933501 1965409 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:33:27.933746 1965409 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:33:27.933916 1965409 main.go:159]           which is applied to the resource directly
I0613 13:33:27.934049 1965409 main.go:166]           and the user is directly included in the role binding directly
```

- `C` user is in a group with direct access

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:35:11.716311 1965696 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:35:12.484470 1965696 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:35:12.484737 1965696 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:35:12.484919 1965696 main.go:159]           which is applied to the resource directly
I0613 13:35:12.485073 1965696 main.go:168]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com ]
```

- `D` user is in a group of groups with direct access

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:37:39.204515 1965883 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:37:40.044236 1965883 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:37:40.044462 1965883 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:37:40.044649 1965883 main.go:159]           which is applied to the resource directly
I0613 13:37:40.044828 1965883 main.go:168]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com   --> group:group_of_groups_1@esodemoapp2.com ]
```

- `E` user has inherited direct bindings

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:39:59.101075 1966054 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:39:59.716914 1966054 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:39:59.716990 1966054 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:39:59.717044 1966054 main.go:162]           which is inherited through resource ancestry [//storage.googleapis.com/fabled-ray-104117-bucket  --> //cloudresourcemanager.googleapis.com/projects/fabled-ray-104117 ]
I0613 13:39:59.717090 1966054 main.go:166]           and the user is directly included in the role binding directly
```

- `F` user has inherited indirect group bindings

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:41:28.331944 1966215 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:41:28.911339 1966215 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:41:28.911586 1966215 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:41:28.911761 1966215 main.go:162]           which is inherited through resource ancestry [//storage.googleapis.com/fabled-ray-104117-bucket  --> //cloudresourcemanager.googleapis.com/projects/fabled-ray-104117 ]
I0613 13:41:28.911910 1966215 main.go:168]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com ]
```

- `G` user has inherited group of group indirect group bindings

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0613 13:44:03.290636 1966413 main.go:108] Getting AnalyzeIamPolicyRequest
I0613 13:44:04.181190 1966413 main.go:154]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0613 13:44:04.181437 1966413 main.go:155]         through role [role:"roles/storage.objectViewer"]
I0613 13:44:04.181603 1966413 main.go:162]           which is inherited through resource ancestry [//storage.googleapis.com/fabled-ray-104117-bucket  --> //cloudresourcemanager.googleapis.com/projects/fabled-ray-104117 ]
I0613 13:44:04.181749 1966413 main.go:168]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com   --> group:group_of_groups_1@esodemoapp2.com ]
```

- `H`: user can impersonate an account which has access to a resource

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"  \
   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest --projectID=fabled-ray-104117 \
   --enableImpersonatedCheck --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0614 07:03:19.161728 2061522 main.go:116] Getting AnalyzeIamPolicyRequest
I0614 07:03:21.788112 2061522 main.go:232]       Result written to gs://fabled-ray-104117-bucket/20210614110319
I0614 07:03:22.058112 2061522 main.go:955]           user:user4@esodemoapp2.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:03:22.058180 2061522 main.go:948]           serviceAccount:impersonated-account@fabled-ray-104117.iam.gserviceaccount.com has iam permissions roles/storage.objectViewer  on //storage.googleapis.com/fabled-ray-104117-bucket

```

- `I`: user can impersonate an account which impersonate another account that has access to a resource

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"  \
    --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr  \
    --useIAMPolicyRequest --projectID=fabled-ray-104117 \
    --enableImpersonatedCheck --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0614 07:05:02.239110 2061693 main.go:116] Getting AnalyzeIamPolicyRequest
I0614 07:05:04.781068 2061693 main.go:232]       Result written to gs://fabled-ray-104117-bucket/20210614110502
I0614 07:05:04.996068 2061693 main.go:955]           user:user4@esodemoapp2.com can impersonate recaptcha-sa@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:05:04.996492 2061693 main.go:955]           serviceAccount:recaptcha-sa@fabled-ray-104117.iam.gserviceaccount.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:05:04.996567 2061693 main.go:948]           serviceAccount:impersonated-account@fabled-ray-104117.iam.gserviceaccount.com has iam permissions roles/storage.objectViewer  on //storage.googleapis.com/fabled-ray-104117-bucket
```

- `J`: user can impersonate a service accoun that has access to a bucket **AND** has direct access to that bucket

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"  \
    --identity="user:user4@esodemoapp2.com"     --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest    --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0622 09:22:31.428417 2936466 main.go:115] Getting AnalyzeIamPolicyRequest
I0622 09:22:33.565845 2936466 main.go:162]       user:user4@esodemoapp2.com has access to resource [full_resource_name:"//storage.googleapis.com/fabled-ray-104117-bucket"]
I0622 09:22:33.566010 2936466 main.go:163]         through [permission:"storage.objects.get" role:"roles/storage.objectViewer" permission:"storage.objects.list"]
I0622 09:22:33.566135 2936466 main.go:167]           which is applied to the resource directly
I0622 09:22:33.566233 2936466 main.go:176]           and the user is included in the role binding through a group hierarchy: [user:user4@esodemoapp2.com  --> group:group4_7@esodemoapp2.com   --> group:group_of_groups_1@esodemoapp2.com ]
I0622 09:22:33.566339 2936466 main.go:961]           user:user4@esodemoapp2.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
I0622 09:22:33.566360 2936466 main.go:954]           serviceAccount:impersonated-account@fabled-ray-104117.iam.gserviceaccount.com has iam permissions roles/storage.objectViewer  on //storage.googleapis.com/fabled-ray-104117-bucket
```

- `K`: user can impersonate two service accounts:  one with direct access to a resource, one that impersonates another service account with access to a resource

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"  \
   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest \
   --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0614 07:07:59.976997 2062996 main.go:116] Getting AnalyzeIamPolicyRequest
I0614 07:08:02.577478 2062996 main.go:232]       Result written to gs://fabled-ray-104117-bucket/20210614110759
I0614 07:08:02.813079 2062996 main.go:955]           user:user4@esodemoapp2.com can impersonate recaptcha-sa@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:08:02.813214 2062996 main.go:955]           serviceAccount:recaptcha-sa@fabled-ray-104117.iam.gserviceaccount.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:08:02.813252 2062996 main.go:948]           serviceAccount:impersonated-account@fabled-ray-104117.iam.gserviceaccount.com has iam permissions roles/storage.objectViewer  on //storage.googleapis.com/fabled-ray-104117-bucket
I0614 07:08:02.813332 2062996 main.go:955]           user:user4@esodemoapp2.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
I0614 07:08:02.813362 2062996 main.go:948]           serviceAccount:impersonated-account@fabled-ray-104117.iam.gserviceaccount.com has iam permissions roles/storage.objectViewer  on //storage.googleapis.com/fabled-ray-104117-buck
```

- `L`: user can impersonate a service account but that account does not have permissions on the resource

```log
$ go run main.go   --checkResource="//storage.googleapis.com/fabled-ray-104117-bucket"   --identity="user:user4@esodemoapp2.com"  \
   --scope="projects/fabled-ray-104117"  -v 20 -alsologtostderr   --useIAMPolicyRequest \
   --projectID=fabled-ray-104117 --gcsDestinationForLongRunningAnalysis=gs://fabled-ray-104117-bucket

I0614 07:28:02.485747 2068876 main.go:116] Getting AnalyzeIamPolicyRequest
I0614 07:28:08.948430 2068876 main.go:232]       Result written to gs://fabled-ray-104117-bucket/20210614112802
I0614 07:28:09.217923 2068876 main.go:955]           user:user4@esodemoapp2.com can impersonate impersonated-account@fabled-ray-104117.iam.gserviceaccount.com
```

- `M`: user is a member of a group which  can impersonate an account which impersonate another account that has access to a resource

** Doesn't work **

### PolicyTroubleshooter

As mentioned, you can also use the PolicyTroubleshooter API to help answer question `B`.  However, it does not seem to elaborate on the group hierarchy nor the IAM resource hierarchy

```bash
 go run main.go   --checkResource="//storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket"   --identity="user4@esodemoapp2.com"  \
   --usePolicyTroubleshooter --permissionToCheck=storage.objects.get --projectID fabled-ray-104117    -v 20 -alsologtostderr 

I0613 14:24:31.180394 1974747 main.go:183] Getting PolicyTroubleshooter
I0613 14:24:32.138580 1974747 main.go:215]    User's AccessState GRANTED
I0613 14:24:32.138751 1974747 main.go:219]    User's AccessState granted at //cloudresourcemanager.googleapis.com/projects/fabled-ray-104117
I0613 14:24:32.142876 1974747 main.go:225]    within which the user has binding with permission via roles roles/storage.objectViewer
I0613 14:24:32.142984 1974747 main.go:226]    through membership map[group:group_of_groups_1@esodemoapp2.com:membership:MEMBERSHIP_INCLUDED  relevance:HIGH]
```

which is equivalent to running:

```bash
gcloud policy-troubleshoot iam //storage.googleapis.com/projects/_/buckets/fabled-ray-104117-bucket    --permission=storage.objects.get --principal-email=user4@esodemoapp2.com
```


---
