
## IAM Permission Verification


Utility functions which testes if the current user or serviceAccount has the subset of permissions that could potentially apply to a Resource.

In other words, if a Resource can potentially have permissions `[A,B,C,E,F,G]`, this script will enumerate those as list which of those permissions the current user has (eg, maybe just `[B,F,G]` for example (bfg9K!)).

This script utilizes an API functions many GCP Services now include:

- [Testing Permissions](https://cloud.google.com/iam/docs/testing-permissions)
- [QueryTestablePermissions](https://pkg.go.dev/google.golang.org/api/iam/v1#PermissionsService.QueryTestablePermissions)
- [Testable IAM Resource Names](https://cloud.google.com/iam/docs/full-resource-names)

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

Provided utility accepts the following parameters

| Option | Description |
|:------------|-------------|
| **`checkResource`** | `string` The canonical resource name to verify |
| **`identity`** | `string` The user or serviceAccount to verify |
| **`scope`** | `string` Scanning scope (`projects/projectID`,`organization/organizationNumber`)|
| **`useIAMPolicyRequest`** | `bool` Invoke `AnalyzeIamPolicyRequest` on the resource and user (`default: false`) |

If run with high verbosity (`-v 20 -alsologtostderr`) output of the script, the current applicable permissions are listed and after that, each of those are tested against the resource.  Any permission that succeeds will be shown below the segment `User permission  on resource:`


### BigQuery Tables

```bash
$ go run main.go \
  --checkResource="//bigquery.googleapis.com/projects/fabled-ray-104117/datasets/test/tables/person" \
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
  --scope="projects/fabled-ray-104117" \
  -v 20 -alsologtostderr
```

### IAP AppEngine


>> Note: use the _Project Number_  (not ID) in the ResourceURL

```bash
$ go run main.go \
  --checkResource="//iap.googleapis.com/projects/248066739582/iap_web/appengine-fabled-ray-104117/services/default" \
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
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
  --identity="user4@esodemoapp2.com" \
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


### GCE Instance

```bash
go run main.go --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/zones/us-central1-a/instances/external"  \
      --identity="user4@esodemoapp2.com"   \
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
      --identity="user4@esodemoapp2.com"   \
      --scope="projects/fabled-ray-104117" \
      -v 20 -alsologtostderr
```

### Compute Engine SubNetworks
	
```bash
go run main.go --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/regions/us-central1/subnetworks/default"  \
      --identity="user4@esodemoapp2.com"   \
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
      --identity="user4@esodemoapp2.com"   \
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
      --identity="user4@esodemoapp2.com"   \
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
$ go run main.go --checkResource="//cloudresourcemanager.googleapis.com/projects/fabled-ray-104117"        --identity="user4@esodemoapp2.com"         --scope="projects/fabled-ray-104117"       -v 10 -alsologtostderr
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

### Misc

#### AnalyzeIamPolicy

Analyzes IAM policies to answer which identities have what accesses on which resources.  

This flag is intended to be used only by a domain Administrator to check which policies are in effect for a given user.  It is NOT intended to be used by a user checking if he/she has access to a resource.

See
- [Analyzing IAM Policy](https://cloud.google.com/asset-inventory/docs/analyzing-iam-policy)
- [analyzeIamPolicy](https://cloud.google.com/asset-inventory/docs/reference/rest/v1p4beta1/TopLevel/analyzeIamPolicy)

Sample output when run by an administrator would show the resource and IAM Role the specified user (`user4@esodemoapp2.com`) has 

```bash
$ go run main.go \
  --checkResource="//compute.googleapis.com/projects/fabled-ray-104117/zones/us-central1-a/instances/os-login" \
  --identity="user4@esodemoapp2.com" \
  --scope="projects/fabled-ray-104117"\
  -v 20 -alsologtostderr \
  --useIAMPolicyRequest

...
...
I0215 08:02:11.625255   26964 main.go:370]      compute.instances.useReadOnly
I0215 08:02:11.625307   26964 main.go:370]      resourcemanager.resourceTagBindings.create
I0215 08:02:11.625360   26964 main.go:370]      resourcemanager.resourceTagBindings.delete
I0215 08:02:11.625412   26964 main.go:370]      resourcemanager.resourceTagBindings.list
I0215 08:02:11.625707   26964 main.go:580] Getting AnalyzeIamPolicyRequest
I0215 08:02:12.227826   26964 main.go:610]     AnalysisResults.Resources [full_resource_name:"//compute.googleapis.com/projects/fabled-ray-104117/zones/us-central1-a/instances/os-login"]
I0215 08:02:12.227992   26964 main.go:611]     AnalysisResults.Accesses [role:"roles/compute.osLogin"]
```

AnalyzeIamPolicy currently executes synchronously and may not be complete in time (todo: use long running) 