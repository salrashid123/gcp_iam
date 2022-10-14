package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"

	//"google.golang.org/protobuf"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	gcperrors "github.com/salrashid123/gcp_error_handler/golang/errors"

	"google.golang.org/api/bigquery/v2"

	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iap/v1"
	"google.golang.org/api/run/v2"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/storage/v1"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	//"google.golang.org/api/container/v1"

	"google.golang.org/api/iam/v1"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"

	policytroubleshooter "cloud.google.com/go/policytroubleshooter/apiv1"
	policypb "google.golang.org/genproto/googleapis/cloud/policytroubleshooter/v1"

	storageAPI "cloud.google.com/go/storage"
)

// https://cloud.google.com/iam/docs/full-resource-names
const (
	bigqueryTablesRegex              = "//bigquery.googleapis.com/projects/(.+)/datasets/(.+)/tables/(.+)"
	bigqueryDatasetRegex             = "//bigquery.googleapis.com/projects/(.+)/datasets/(.+)"
	iamServiceAccountsRegex          = "//iam.googleapis.com/projects/(.+)/serviceAccounts/(.+)"
	serviceAccountsKeysRegex         = "//iam.googleapis.com/projects/(.+)/serviceAccounts/(.+)/keys/(.+)"
	iapAppEngineRegex                = "//iap.googleapis.com/projects/(.+)/iap_web/appengine-(.+)/services/(.+)"
	iapGCERegex                      = "//iap.googleapis.com/projects/(.+)/iap_web/compute/services/(.+)"
	spannerInstances                 = "//spanner.googleapis.com/projects/(.+)/instances/(.+)"
	storageBucketsRegex              = "//storage.googleapis.com/projects/_/buckets/(.+)"
	computeInstanceRegex             = "//compute.googleapis.com/projects/(.+)/zones/(.+)/instances/(.+)$"
	computeNetworksRegex             = "//compute.googleapis.com/projects/(.+)/global/networks/(.+)"
	computeSubNetworksRegex          = "//compute.googleapis.com/projects/(.+)/regions/(.+)/subnetworks/(.+)"
	kubernetesEngineRegex            = "//container.googleapis.com/projects/(.+)/clusters/(.+)"
	pubsubTopicsRegex                = "//pubsub.googleapis.com/projects/(.+)/topics/(.+)"
	resourceManagerOrganizationRegex = "//cloudresourcemanager.googleapis.com/organizations/(.+)"
	resourceManagerProjectsRegex     = "//cloudresourcemanager.googleapis.com/projects/(.+)"
	resourceManagerFoldersRegex      = "//cloudresourcemanager.googleapis.com/folders/(.+)"
	cloudRunRegex                    = "//run.googleapis.com/projects/(.+)/locations/(.+)/services/(.+)"

	// https://cloud.google.com/asset-inventory/docs/supported-asset-types#analyzable_asset_types

	assetTypeBQDataset         = "bigquery.googleapis.com/Dataset"
	assetTypeBQTable           = "bigquery.googleapis.com/Table"
	assetTypeGCS               = "storage.googleapis.com/Bucket"
	assetTypeAppEngineService  = "appengine.googleapis.com/Service"
	assetTypeBackendService    = "compute.googleapis.com/BackendService"
	assetTypeFolder            = "cloudresourcemanager.googleapis.com/Folder"
	assetTypeOrganization      = "cloudresourcemanager.googleapis.com/Organization"
	assetTypeProject           = "cloudresourcemanager.googleapis.com/Project"
	assetTypeServiceAccount    = "iam.googleapis.com/ServiceAccount"
	assetTypeServiceAccountKey = "iam.googleapis.com/ServiceAccountKey"
	assetTypeGCEInstance       = "compute.googleapis.com/Instance"
	assetTypeCloudRunService   = "run.googleapis.com/Service"

	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	scope                      = flag.String("scope", "", "Scope to check")
	checkResource              = flag.String("checkResource", "", "Canonical Resource to check //storage.googleapis.com/projects/_/buckets/(.+)")
	identity                   = flag.String("identity", "", "Permission to check")
	impersonateServiceAccount  = flag.String("impersonateServiceAccount", "", "ServiceAccount to impersonate")
	printPermissionsOnResource = flag.Bool("printPermissionsOnResource", false, "PrintPermission on target Resource")
	useIAMPolicyRequest        = flag.Bool("useIAMPolicyRequest", false, "Use IAMPolicy API request (requires admin)")
	projectID                  = flag.String("projectID", "", "ProjectID for quota")

	usePolicyTroubleshooter              = flag.Bool("usePolicyTroubleshooter", false, "Use policytroubleshooter API to check a given permission (requires admin)")
	permissionToCheck                    = flag.String("permissionToCheck", "", "Permission to check using policytroubleshooter API (requires admin)")
	enableImpersonatedCheck              = flag.Bool("enableImpersonatedCheck", false, "Check for Impersonated credentials (default: false)")
	checkEndUserPermissions              = flag.Bool("checkEndUserPermissions", false, "Enumerate end user permissions (default: false)")
	gcsDestinationForLongRunningAnalysis = flag.String("gcsDestinationForLongRunningAnalysis", "", "Destination gcs bucket to write LongRunningAnalysis (in format gcs://fabled-ray-104117-bucket)")
)

func init() {
}

func getPermissions(ctx context.Context, ts oauth2.TokenSource, resource string) ([]string, error) {
	glog.V(2).Infof("================ QueryTestablePermissions with Resource ======================\n")
	glog.V(2).Infof("   %s \n ", resource)

	if *checkResource == "" {
		return nil, errors.New("must specify checkResource")
	}

	iamService, err := iam.NewService(ctx, option.WithQuotaProject(*projectID))
	if err != nil {
		glog.Fatal(err)
	}
	ors := iam.NewPermissionsService(iamService)

	var permstoTest []string

	perms := make([]*iam.Permission, 0)
	nextPageToken := ""
	for {
		ps, err := ors.QueryTestablePermissions(&iam.QueryTestablePermissionsRequest{
			FullResourceName: resource,
			PageToken:        nextPageToken,
		}).Do()
		if err != nil {
			return nil, errors.New("could not iterate testable permissions")
		}
		glog.V(20).Infof("================ Getting Permissions %v\n", ps.NextPageToken)

		for _, sa := range ps.Permissions {
			glog.V(30).Infof("            Adding Permission to check %s\n", sa.Name)
			perms = append(perms, sa)
		}

		nextPageToken = ps.NextPageToken
		if nextPageToken == "" {
			break
		}

	}

	glog.V(15).Infof("Testable permissions on resource:\n")
	for _, p := range perms {
		glog.V(20).Infof("     %s", p.Name)
		permstoTest = append(permstoTest, p.Name)
	}

	return permstoTest, nil
}

func main() {
	flag.Parse()

	ctx := context.Background()

	s := []string{cloudPlatformScope}

	var err error
	var ts oauth2.TokenSource

	if *impersonateServiceAccount != "" {
		if *checkEndUserPermissions {
			glog.V(10).Infof("Impersonating User using service Account")
			// just users are supported
			email := strings.TrimPrefix(*identity, "user:")
			ts, err = impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
				TargetPrincipal: *impersonateServiceAccount,
				Scopes:          s,
				Subject:         email,
			})
		} else {
			ts, err = impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
				TargetPrincipal: *impersonateServiceAccount,
				Scopes:          s,
			})
		}
	} else {
		ts, err = google.DefaultTokenSource(ctx)
	}
	if err != nil {
		glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
		return
	}

	var permstoTest []string
	if *printPermissionsOnResource {
		// Test Permississons
		permstoTest, err := getPermissions(ctx, ts, *checkResource)
		if err != nil {
			glog.Fatal(err)
		}
		err = verifyPermissionsAsUser(ctx, ts, *checkResource, permstoTest)
		if err != nil {
			glog.Fatal(err)
		}
		return
	}

	// ***************************************************************************************************

	if *useIAMPolicyRequest {

		glog.V(2).Infof("Getting AnalyzeIamPolicyRequest")
		creds, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			glog.Fatal(err)
		}
		proj := creds.ProjectID

		if *projectID != "" {
			proj = *projectID
		}
		assetClient, err := asset.NewClient(ctx, option.WithQuotaProject(proj), option.WithTokenSource(ts))
		if err != nil {
			glog.Fatal(err)
		}

		if *identity == "" {
			glog.Fatal("--identity flag required for AnalyzeIamPolicyRequest")
		}
		if !*enableImpersonatedCheck {
			req := &assetpb.AnalyzeIamPolicyRequest{
				AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
					Scope: *scope,
					ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
						FullResourceName: *checkResource,
					},
					IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
						Identity: *identity,
					},
					Options: &assetpb.IamPolicyAnalysisQuery_Options{
						ExpandGroups:                       true,
						OutputGroupEdges:                   true,
						ExpandResources:                    true,
						ExpandRoles:                        true,
						OutputResourceEdges:                true,
						AnalyzeServiceAccountImpersonation: *enableImpersonatedCheck,
					},
				},
			}
			resp, err := assetClient.AnalyzeIamPolicy(ctx, req)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			for _, result := range resp.MainAnalysis.AnalysisResults {

				for _, acl := range result.AccessControlLists {
					glog.V(2).Infof("      %s has access to resource %s", *identity, acl.Resources)
					glog.V(2).Infof("        with capability %s", acl.Accesses)
					glog.V(2).Infof("        from node [%s]\n", result.AttachedResourceFullName)
				}

				if result.IamBinding.Condition != nil {
					glog.V(2).Infof("        With Condition [%s]\n", result.IamBinding.Condition.Expression)
				}

				if stringInSlice(*identity, result.IamBinding.Members) {
					glog.V(2).Info("          user is directly included in the role binding ")
				} else {
					glog.V(2).Info("          user is included in the role binding through a group hierarchy: ", getIdentityAncestry(result.IdentityList, *identity, []string{*identity}))
				}
			}
			if len(resp.MainAnalysis.AnalysisResults) == 0 {
				glog.V(2).Infof("      %s does not access to resource %s", *identity, *checkResource)
			}
		} else {
			fileName := time.Now().UTC().Format("20060102150405")
			req := &assetpb.AnalyzeIamPolicyLongrunningRequest{
				AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
					Scope: *scope,
					ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
						FullResourceName: *checkResource,
					},
					IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
						Identity: *identity,
					},
					Options: &assetpb.IamPolicyAnalysisQuery_Options{
						ExpandGroups:                       true,
						OutputGroupEdges:                   true,
						ExpandResources:                    true,
						ExpandRoles:                        true,
						OutputResourceEdges:                true,
						AnalyzeServiceAccountImpersonation: *enableImpersonatedCheck,
					},
				},
				OutputConfig: &assetpb.IamPolicyAnalysisOutputConfig{
					Destination: &assetpb.IamPolicyAnalysisOutputConfig_GcsDestination_{
						GcsDestination: &assetpb.IamPolicyAnalysisOutputConfig_GcsDestination{
							Uri: fmt.Sprintf("%s/%s", *gcsDestinationForLongRunningAnalysis, fileName),
						},
					},
				},
			}

			op, err := assetClient.AnalyzeIamPolicyLongrunning(ctx, req)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}

			_, err = op.Wait(ctx)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}

			glog.V(2).Infof("      Result written to %s", fmt.Sprintf("%s/%s", *gcsDestinationForLongRunningAnalysis, fileName))

			gcsClient, err := storageAPI.NewClient(ctx)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			defer gcsClient.Close()
			bkt := gcsClient.Bucket(strings.TrimPrefix(*gcsDestinationForLongRunningAnalysis, "gs://"))

			rc, err := bkt.Object(fileName).NewReader(ctx)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			defer rc.Close()
			slurp, err := ioutil.ReadAll(rc)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			resp := assetpb.AnalyzeIamPolicyResponse{}
			var um = jsonpb.Unmarshaler{}
			um.AllowUnknownFields = true
			err = um.Unmarshal(bytes.NewReader(slurp), &resp)
			if err != nil {
				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			glog.V(20).Infof("      Parsed AnalyzeIamPolicyResponse from %s", fmt.Sprintf("%s/%s", *gcsDestinationForLongRunningAnalysis, fileName))

			for _, result := range resp.MainAnalysis.AnalysisResults {

				for _, acl := range result.AccessControlLists {
					glog.V(2).Infof("      %s has access to resource %s", *identity, acl.Resources)
					glog.V(2).Infof("         with capability %s", acl.Accesses)
					glog.V(2).Infof("         from node [%s]\n", result.AttachedResourceFullName)
				}

				if result.IamBinding.Condition != nil {
					glog.V(2).Infof("         With Condition [%s]\n", result.IamBinding.Condition.Expression)
				}

				if stringInSlice(*identity, result.IamBinding.Members) {
					glog.V(2).Info("          user is directly included in the role binding ")
				} else {
					glog.V(2).Info("          user is included in the role binding through a group hierarchy: ", getIdentityAncestry(result.IdentityList, *identity, []string{*identity}))
				}
			}
			recurseDelegationForResource(*identity, *checkResource, resp)
		}

		return
	} else if *usePolicyTroubleshooter {
		if *permissionToCheck == "" || *checkResource == "" || *identity == "" {
			glog.Errorf("Specify,  permissionToCheck, checkResource and identity must be specified")
			return
		}

		glog.V(2).Infof("Getting PolicyTroubleshooter")

		if len(strings.Split(*identity, ":")) > 1 {
			*identity = strings.Split(*identity, ":")[1]
		}
		creds, err := google.FindDefaultCredentials(ctx)
		if err != nil {
			glog.Fatal(err)
		}
		proj := creds.ProjectID

		if *projectID != "" {
			proj = *projectID
		}
		policyClient, err := policytroubleshooter.NewIamCheckerClient(ctx, option.WithQuotaProject(proj), option.WithTokenSource(ts))
		if err != nil {
			glog.Fatal(err)
		}
		req := &policypb.TroubleshootIamPolicyRequest{
			AccessTuple: &policypb.AccessTuple{
				Principal:        *identity,
				FullResourceName: *checkResource,
				Permission:       *permissionToCheck,
			},
		}
		resp, err := policyClient.TroubleshootIamPolicy(ctx, req)
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return
		}

		glog.V(10).Infof("   User's AccessState %s\n", resp.Access)

		for _, r := range resp.ExplainedPolicies {
			if r.Access == policypb.AccessState_GRANTED {
				glog.V(10).Infof("   User's AccessState granted at %s\n", r.FullResourceName)
				// for _, b := range r.Policy.Bindings {
				// 	glog.V(20).Infof("       which has roles %s\n", b.Role)
				// }
				for _, be := range r.BindingExplanations {
					if be.Access == policypb.AccessState_GRANTED {
						glog.V(10).Infof("   user has binding with permission via roles %s\n", be.Role)
						glog.V(10).Infof("   through membership %s\n", be.Memberships)
					}
				}
			}
			if r.Access == policypb.AccessState_UNKNOWN_CONDITIONAL {
				glog.V(10).Infof("   User may have Conditional access %s\n", r.FullResourceName)
			}
		}
	}

	glog.V(10).Infof("================ Determining Hierarchy for resource %s\n", *checkResource)

	err = getScopedRoles(ctx, ts, *checkResource, *scope, permstoTest)
	if err != nil {
		err := handleError(err)
		if err != nil {
			glog.Fatal(err)
		}
		return
	}
}

func getScopedRoles(ctx context.Context, ts oauth2.TokenSource, resource string, scope string, permissionList []string) error {

	glog.V(2).Infof("Getting ScopedPermission for resource [%s] in scope [%s]", resource, scope)

	// TODO: combine code below with verifyPermissionAsUser() function since the same checks are done there

	var assetType string
	var query string

	// BQ Tables
	// bigquery.googleapis.com/projects/project-id/datasets/dataset-id/tables/table-id
	// bigqueryTablesRegex  = "//bigquery.googleapis.com/projects/(.+)/datasets/(.+)/tables/(.+)"
	re := regexp.MustCompile(bigqueryTablesRegex)
	res := re.FindStringSubmatch(resource)
	if len(res) == 4 {
		glog.V(2).Infof("==== Scoped Resource is BigQuery Table ==== %s\n", res[1])
		var bigQueryService *bigquery.Service
		assetType = assetTypeBQTable
		query = res[3]

		bigQueryService, err := bigquery.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}
		resource := fmt.Sprintf("projects/%s/datasets/%s/tables/%s", res[1], res[2], res[3])
		p, err := bigQueryService.Tables.GetIamPolicy(resource, &bigquery.GetIamPolicyRequest{}).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range p.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}
	// BQ Dataset
	// bigquery.googleapis.com/projects/project-id/datasets/dataset-id
	// bigqueryDatasetRegex  = "//bigquery.googleapis.com/projects/(.+)/datasets/(.+)"
	re = regexp.MustCompile(bigqueryDatasetRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 3 {
		glog.V(2).Infof("==== Scoped Resource is BigQuery Dataset ==== %s\n", res[1])

		assetType = assetTypeBQDataset
		query = res[2]
		var bigQueryService *bigquery.Service

		bigQueryService, err := bigquery.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}
		//resource := fmt.Sprintf("projects/%s/datasets/%s", res[1], res[2])
		p, err := bigQueryService.Datasets.Get(res[1], res[2]).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range p.Access {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// ServiceAccounts
	// iam.googleapis.com/projects/project-id/serviceAccounts/service-account-email
	// iamServiceAccountsRegex          = "//iam.googleapis.com/projects/(.+)/serviceAccounts/(.+)"

	re = regexp.MustCompile(iamServiceAccountsRegex)
	res = re.FindStringSubmatch(*checkResource)
	if len(res) == 3 {
		glog.V(2).Infof("==== Scoped Resource is Service Accounts ==== %s\n", res[2])
		assetType = assetTypeGCS
		query = res[1]

		iamService, err := iam.NewService(ctx)
		if err != nil {
			glog.Fatal(err)
		}

		svcAccountPolicy, err := iamService.Projects.ServiceAccounts.GetIamPolicy(fmt.Sprintf("projects/%s/serviceAccounts/%s", res[1], res[2])).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range svcAccountPolicy.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// IAP AppEngine
	//	//iap.googleapis.com/projects/project-number/iap_web/appengine-project-id/services/app-service-id
	// iapAppEngineRegex = "//iap.googleapis.com/projects/(.+)/iap_web/appengine-(.+)/services/(.+)"
	re = regexp.MustCompile(iapAppEngineRegex)
	res = re.FindStringSubmatch(*checkResource)
	if len(res) == 4 {
		glog.V(2).Infof("==== Resource is IAP AppEngine Resource ==== %s\n", res[2])

		assetType = assetTypeAppEngineService
		query = res[2]
		var iapService *iap.Service

		iapService, err := iap.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := iapService.V1.GetIamPolicy(fmt.Sprintf("projects/%s/iap_web/appengine-%s/services/%s", res[1], res[2], res[3]), &iap.GetIamPolicyRequest{}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// GCS:
	//   assetTypeGCS=storage.googleapis.com/Bucket
	//   storageBucketsRegex="//storage.googleapis.com/projects/_/buckets/(.+)"
	re = regexp.MustCompile(storageBucketsRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 2 {
		glog.V(2).Infof("==== Scoped Resource is GCS Bucket ==== %s\n", res[1])
		assetType = assetTypeGCS
		query = res[1]

		storageClient, err := storageAPI.NewClient(ctx)
		if err != nil {
			glog.Fatal(err)
		}

		bkt := storageClient.Bucket(res[1])

		p, err := bkt.IAM().Policy(ctx)
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		// TODO: handle custom roles and conditions
		// `projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}
		for _, n := range p.Roles() {
			glog.V(2).Infof("       Roles ==== %s\n", n)
			//    roles/storage.objectViewer_withcond_71ee91d0ed30fbae053c
			// oirsp, err := ors.Get(string(n)).Do()
			// if err != nil {
			// 	err := handleError(err)
			// 	if err != nil {
			// 		glog.Fatal(err)
			// 	}
			// 	return nil, err
			// }
			// glog.V(2).Infof("          Role Description ==== %v\n", oirsp.IncludedPermissions)
		}
	}

	// IAP Backend Service
	//  iap.googleapis.com/projects/project-number/iap_web/compute/services/backend-service-id or backend-service-name
	// iapGCERegex  = "//iap.googleapis.com/projects/(.+)/iap_web/compute/services/(.+)""
	re = regexp.MustCompile(iapGCERegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 3 {
		glog.V(2).Infof("==== Scoped Resource is IAP Backend Service ==== %s\n", res[2])

		assetType = assetTypeBackendService
		query = res[2]
		var iapService *iap.Service

		iapService, err := iap.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := iapService.V1.GetIamPolicy(fmt.Sprintf("projects/%s/iap_web/compute/services/%s", res[1], res[2]), &iap.GetIamPolicyRequest{}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// GCE Instance
	//  "compute.googleapis.com/Instance"
	// //compute.googleapis.com/projects/project-id/zones/zone/instances/instance-id
	// computeInstanceRegex  = "//compute.googleapis.com/projects/(.+)/zones/(.+)/instances/(.+)$"
	re = regexp.MustCompile(computeInstanceRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 4 {
		glog.V(2).Infof("==== Scoped Resource is GCE Instance ==== %s\n", res[3])

		assetType = assetTypeGCEInstance
		query = res[3]
		var computeService *compute.Service

		computeService, err := compute.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := computeService.Instances.GetIamPolicy(res[1], res[2], res[3]).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// Projects
	// resourceManagerProjectsRegex     = "//cloudresourcemanager.googleapis.com/projects/(.+)"
	// assetTypeProject           = "cloudresourcemanager.googleapis.com/Project"
	re = regexp.MustCompile(resourceManagerProjectsRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 2 {
		glog.V(2).Infof("==== Scoped Resource is Project ==== %s\n", res[1])

		assetType = assetTypeProject
		query = res[1]
		var crmService *crmv1.Service

		crmService, err := crmv1.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := crmService.Projects.GetIamPolicy(res[1], &crmv1.GetIamPolicyRequest{}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}
	}

	// Folders
	// resourceManagerFoldersRegex      = "//cloudresourcemanager.googleapis.com/folders/(.+)"
	// assetTypeFolder            = "cloudresourcemanager.googleapis.com/Folder"
	re = regexp.MustCompile(resourceManagerFoldersRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 2 {
		glog.V(2).Infof("==== Scoped Resource is Folder ==== %s\n", res[1])

		assetType = assetTypeFolder
		query = res[1]
		var crmService2 *crmv2.Service

		crmService2, err := crmv2.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := crmService2.Folders.GetIamPolicy(fmt.Sprintf("folders/%s", res[1]), &crmv2.GetIamPolicyRequest{}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}

		f, err := crmService2.Folders.Get(fmt.Sprintf("folders/%s", res[1])).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof("       Folder: [%s]\n", f.Name)
		ppolicy, err := crmService2.Folders.GetIamPolicy(f.Name, &crmv2.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ppolicy.Bindings {
			glog.V(10).Infof("                Policy Binding %s", b.Role)
		}
	}

	// Organization
	// resourceManagerOrganizationRegex      = "//cloudresourcemanager.googleapis.com/organizations/(.+)"
	// assetTypeFolder            = "cloudresourcemanager.googleapis.com/Organization"
	re = regexp.MustCompile(resourceManagerOrganizationRegex)
	res = re.FindStringSubmatch(resource)
	if len(res) == 2 {
		glog.V(2).Infof("==== Scoped Resource is Folder ==== %s\n", res[1])

		assetType = assetTypeOrganization
		query = res[1]
		var crmService1 *crmv1.Service

		crmService1, err := crmv1.NewService(ctx, option.WithTokenSource(ts))
		if err != nil {
			return err
		}

		ciamResp, err := crmService1.Organizations.GetIamPolicy(fmt.Sprintf("organizations/%s", res[1]), &crmv1.GetIamPolicyRequest{}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ciamResp.Bindings {
			glog.V(2).Infof("       Roles ==== %s\n", b.Role)
		}

		f, err := crmService1.Organizations.Get(fmt.Sprintf("organizations/%s", res[1])).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof("       Organizations: [%s]\n", f.Name)
		ppolicy, err := crmService1.Organizations.GetIamPolicy(f.Name, &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		for _, b := range ppolicy.Bindings {
			glog.V(10).Infof("                Policy Binding %s", b.Role)
		}
	}

	//*******************************************************************************************************************

	glog.V(2).Infof("       SearchingAssets of type [%s] with query [name:%s] \n", assetType, query)

	if assetType == assetTypeFolder || assetType == assetTypeOrganization {
		glog.V(2).Infof("     AssetType [%s] does not support GetAncestry()", assetType)
		return nil
	}
	assetClient, err := asset.NewClient(ctx, option.WithQuotaProject(*projectID), option.WithTokenSource(ts))
	if err != nil {
		glog.Fatal(err)
	}
	req := &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		AssetTypes: []string{assetType},
		Query:      fmt.Sprintf("name:%s", query),
	}
	respItr := assetClient.SearchAllResources(ctx, req)
	for {
		r, err := respItr.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		crmService1, err := crmv1.NewService(ctx)
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		crmService2, err := crmv2.NewService(ctx)
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		// uri: https://cloudresourcemanager.googleapis.com/v1/projects/cicp-oidc:getAncestry?alt=json
		pss, err := crmService1.Projects.GetAncestry(strings.TrimLeft(r.Project, "projects/"), &crmv1.GetAncestryRequest{}).Do()
		if err != nil {
			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}

		for _, a := range pss.Ancestor {
			glog.V(2).Infof("       Ancestor: [%s/%s]\n", a.ResourceId.Type, a.ResourceId.Id)

			// https://cloudresourcemanager.googleapis.com/v1/projects/cicp-oidc:getIamPolicy?alt=json
			if a.ResourceId.Type == "project" {
				glog.V(10).Infof("       Project: [%s]\n", a.ResourceId.Id)

				ppolicy, err := crmService1.Projects.GetIamPolicy(a.ResourceId.Id, &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
				if err != nil {
					err := handleError(err)
					if err != nil {
						glog.Fatal(err)
					}
					return err
				}
				for _, b := range ppolicy.Bindings {
					glog.V(10).Infof("                Policy Binding %s", b.Role)
				}
			}
			// https://cloudresourcemanager.googleapis.com/v2/folders/750467892309:getIamPolicy?alt=json
			if a.ResourceId.Type == "folder" {
				glog.V(2).Infof("       Folder: [%s]\n", a.ResourceId.Id)
				ppolicy, err := crmService2.Folders.GetIamPolicy(fmt.Sprintf("folders/%s", a.ResourceId.Id), &crmv2.GetIamPolicyRequest{}).Context(ctx).Do()
				if err != nil {
					err := handleError(err)
					if err != nil {
						glog.Fatal(err)
					}
					return err
				}
				for _, b := range ppolicy.Bindings {
					glog.V(10).Infof("                Policy Binding %s", b.Role)
				}
			}

			// https://cloudresourcemanager.googleapis.com/v1/organizations/673208786098:getIamPolicy?alt=json
			if a.ResourceId.Type == "organization" {
				glog.V(2).Infof("       Organization: [%s]\n", a.ResourceId.Id)
				ppolicy, err := crmService1.Organizations.GetIamPolicy(fmt.Sprintf("organizations/%s", a.ResourceId.Id), &crmv1.GetIamPolicyRequest{}).Context(ctx).Do()
				if err != nil {
					err := handleError(err)
					if err != nil {
						glog.Fatal(err)
					}
					return err
				}
				for _, b := range ppolicy.Bindings {
					glog.V(10).Infof("                Policy Binding %s", b.Role)
				}
			}
		}
	}
	return nil
}

func remove(urlList []string, remove []string) []string {
	for i := 0; i < len(urlList); i++ {
		url := urlList[i]
		for _, rem := range remove {
			if url == rem {
				urlList = append(urlList[:i], urlList[i+1:]...)
				i--
				break
			}
		}
	}
	return urlList
}

func handleError(err error) error {
	prettyErrors := gcperrors.New(gcperrors.Error{
		Err:         err,
		PrettyPrint: true,
	})
	glog.Errorf("%s", prettyErrors)
	return err
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func getIdentityAncestry(il *assetpb.IamPolicyAnalysisResult_IdentityList, target string, curr []string) []string {
	for _, l := range il.GroupEdges {
		if l.TargetNode == target {
			return getIdentityAncestry(il, l.SourceNode, append(curr, fmt.Sprintf(" --> %s ", l.SourceNode)))
		}
	}
	return curr
}

func recurseDelegationForResource(lidentity, lresource string, resp assetpb.AnalyzeIamPolicyResponse) {
	for _, result := range resp.ServiceAccountImpersonationAnalysis {
		for _, r := range result.AnalysisResults {
			for _, n := range r.IdentityList.Identities {
				if n.Name == lidentity {
					rn := transformResourceName(r.AttachedResourceFullName, lresource)
					if rn == lresource {
						glog.V(2).Infof("          %s has iam permissions %s  on  [%s]", lidentity, r.IamBinding.Role, r.AttachedResourceFullName)
					}

					if r.IamBinding.Role == "roles/iam.serviceAccountTokenCreator" {
						re := regexp.MustCompile(iamServiceAccountsRegex)
						rg := re.FindStringSubmatch(r.AttachedResourceFullName)
						if len(rg) == 3 {
							glog.V(2).Infof("          %s can impersonate %s", lidentity, rg[2])
							if lidentity == fmt.Sprintf("serviceAccount:%s", rg[2]) {
								glog.V(2).Infof("          %s can self-impersonate, skipping to avoied recursion", rg[2])
							} else {
								recurseDelegationForResource(fmt.Sprintf("serviceAccount:%s", rg[2]), lresource, resp)
							}
						}
					}
				}
			}
		}
	}
}

func transformResourceName(in string, provided string) string {
	if strings.HasPrefix("//storage.googleapis.com/", in) {
		return in
	}
	return provided
}

func verifyPermissionsAsUser(ctx context.Context, ts oauth2.TokenSource, checkResource string, permstoTest []string) error {

	// verify permissions as end-user
	var res []string

	// 	//bigquery.googleapis.com/projects/project-id/datasets/dataset-id
	re := regexp.MustCompile(bigqueryTablesRegex)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 4 {
		glog.V(2).Infof("==== TestIAMPermissions as BigQuery Tables Resource ====\n")
		var bigQueryService *bigquery.Service

		bigQueryService, err := bigquery.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := bigQueryService.Tables.TestIamPermissions(fmt.Sprintf("projects/%s/datasets/%s/tables/%s", res[1], res[2], res[3]), &bigquery.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// 	//iam.googleapis.com/projects/project-id/serviceAccounts/service-account-email

	re = regexp.MustCompile(iamServiceAccountsRegex)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 3 {
		glog.V(2).Infof("==== TestIAMPermissions as ServiceAccounts Resource ====\n")
		var iamService *iam.Service

		iamService, err := iam.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := iamService.Projects.ServiceAccounts.TestIamPermissions(fmt.Sprintf("projects/%s/serviceAccounts/%s", res[1], res[2]), &iam.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	//	//iam.googleapis.com/projects/project-id/serviceAccounts/service-account-email/keys/key-id

	re = regexp.MustCompile(serviceAccountsKeysRegex)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 4 {
		glog.V(2).Infof("==== TestIAMPermissions as ServiceAccount Keys Resource ====\n")
		var iamService *iam.Service

		iamService, err := iam.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			glog.Fatal(err)
		}

		ciamResp, err := iamService.Projects.ServiceAccounts.TestIamPermissions(fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s", res[1], res[2], res[3]), &iam.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	//	//iap.googleapis.com/projects/project-number/iap_web/appengine-project-id/services/app-service-id

	re = regexp.MustCompile(iapAppEngineRegex)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 4 {

		glog.V(2).Infof("==== TestIAMPermissions as IAP AppEngine Resource ==== %s\n", res[2])

		var iapService *iap.Service

		iapService, err := iap.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := iapService.V1.TestIamPermissions(fmt.Sprintf("projects/%s/iap_web/appengine-%s/services/%s", res[1], res[2], res[3]), &iap.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}

	}

	//	//iap.googleapis.com/projects/project-number/iap_web/compute/services/backend-service-id

	re = regexp.MustCompile(iapGCERegex)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 3 {
		glog.V(2).Infof("==== TestIAMPermissions as IAP ComputeEngine Resource ====\n")
		var iapService *iap.Service

		iapService, err := iap.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := iapService.V1.TestIamPermissions(fmt.Sprintf("projects/%s/iap_web/compute/services/%s", res[1], res[2]), &iap.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	//	//spanner.googleapis.com/projects/project-id/instances/instance-id

	re = regexp.MustCompile(spannerInstances)
	res = re.FindStringSubmatch(checkResource)
	if len(res) == 3 {
		glog.V(2).Infof("==== TestIAMPermissions as Spanner Resource ====\n")
		var spannerService *spanner.Service

		spannerService, err := spanner.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := spannerService.Projects.Instances.TestIamPermissions(fmt.Sprintf("projects/%s/instances/%s", res[1], res[2]), &spanner.TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// 	//storage.googleapis.com/projects/_/buckets/bucket-id
	re = regexp.MustCompile(storageBucketsRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 2 {

		glog.V(2).Infof("==== TestIAMPermissions as GCS Bucket Resource ====\n")

		var storageService *storage.Service

		storageService, err := storage.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		// these permissions  haven't propagated out yet as of 2/2/22
		// https://github.com/salrashid123/iam_bq_dataset
		permstoTest = remove(permstoTest, []string{
			"storage.objects.getIamPolicy",
			"storage.objects.setIamPolicy",
			"storage.buckets.createTagBinding",
			"storage.buckets.deleteTagBinding",
			"storage.buckets.listTagBindings",
			"resourcemanager.resourceTagBindings.create",
			"resourcemanager.resourceTagBindings.delete",
			"resourcemanager.resourceTagBindings.list",
			"resourcemanager.hierarchyNodes.createTagBinding",
			"resourcemanager.hierarchyNodes.deleteTagBinding",
			"resourcemanager.hierarchyNodes.listEffectiveTags",
			"resourcemanager.hierarchyNodes.listTagBindings",
		})

		ciamResp, err := storageService.Buckets.TestIamPermissions(res[1], permstoTest).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// 	//run.googleapis.com/projects/project-id/locations/location-id/services/service-id

	re = regexp.MustCompile(cloudRunRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 4 {

		glog.V(2).Infof("==== TestIAMPermissions as Cloud RUn Resource ====\n")

		var err error
		var runService *run.Service

		runService, err = run.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		// these permissions  haven't propagated out yet as of 2/2/22
		// https://github.com/salrashid123/iam_bq_dataset
		permstoTest = remove(permstoTest, []string{})
		ciamResp, err := runService.Projects.Locations.Services.TestIamPermissions(fmt.Sprintf("projects/%s/locations/%s/services/%s", res[1], res[2], res[3]), &run.GoogleIamV1TestIamPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// 	//compute.googleapis.com/projects/project-id/zones/zone/instances/instance-id
	re = regexp.MustCompile(computeInstanceRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 4 {

		glog.V(2).Infof("==== TestIAMPermissions as Compute Instance Resource ====\n")

		var computeService *compute.Service

		computeService, err := compute.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := computeService.Instances.TestIamPermissions(res[1], res[2], res[3], &compute.TestPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// 	//compute.googleapis.com/projects/project-id/global/networks/network
	re = regexp.MustCompile(computeNetworksRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 3 {

		glog.V(2).Infof("==== TestIAMPermissions as Compute Network Resource ====\n")
		return errors.New("Unimplemented")

		// var computeService *compute.Service

		// computeService, err = compute.NewService(ctx, option.WithTokenSource(ts))
		// if err != nil {
		// 	glog.Fatal(err)
		// }

		// ciamResp, err := computeService.Networks.TestIamPermissions(res[1], res[2], res[3], &compute.TestPermissionsRequest{
		// 	Permissions: permstoTest,
		// }).Do()
		// if err != nil {
		// 	glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

		// 	err := handleError(err)
		// 	if err != nil {
		// 		glog.Fatal(err)
		// 	}
		// 	return
		// }
		// glog.V(2).Infof(" User permission  on resource: \n")
		// for _, p := range ciamResp.Permissions {
		// 	glog.V(2).Infof("     %s\n", p)
		// }
	}

	// //compute.googleapis.com/projects/project-id/regions/region/subnetworks/subnetwork
	re = regexp.MustCompile(computeSubNetworksRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 4 {

		glog.V(2).Infof("==== TestIAMPermissions as Compute SubNetwork Resource ====\n")

		var computeService *compute.Service

		computeService, err := compute.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		ciamResp, err := computeService.Subnetworks.TestIamPermissions(res[1], res[2], res[3], &compute.TestPermissionsRequest{
			Permissions: permstoTest,
		}).Do()
		if err != nil {
			glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

			err := handleError(err)
			if err != nil {
				glog.Fatal(err)
			}
			return err
		}
		glog.V(2).Infof(" User permission  on resource: \n")
		for _, p := range ciamResp.Permissions {
			glog.V(2).Infof("     %s\n", p)
		}
	}

	// //container.googleapis.com/projects/project-id/clusters/cluster-id
	re = regexp.MustCompile(kubernetesEngineRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 3 {
		glog.V(2).Infof("==== TestIAMPermissions on Kubernetes Engine Resource ====\n")
		return errors.New("Unimplemented")

		// var containerService *container.Service

		// containerService, err = container.NewService(ctx, option.WithTokenSource(ts))
		// if err != nil {
		// 	glog.Fatal(err)
		// }

		// ciamResp, err := containerService.Clusters.TestIamPermissions(res[1], res[2], &container.TestPermissionsRequest{
		// 	Permissions: permstoTest,
		// }).Do()
		// if err != nil {
		// 	glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

		// 	err := handleError(err)
		// 	if err != nil {
		// 		glog.Fatal(err)
		// 	}
		// 	return
		// }
		// glog.V(2).Infof(" User permission  on resource: \n")
		// for _, p := range ciamResp.Permissions {
		// 	glog.V(2).Infof("     %s\n", p)
		// }
	}

	// 	//cloudresourcemanager.googleapis.com/organizations/numeric-id
	re = regexp.MustCompile(resourceManagerOrganizationRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 2 {
		glog.V(2).Infof("==== TestIAMPermissions on Organizations ====\n")

		var crmService *crmv1.Service

		crmService, err := crmv1.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		if len(permstoTest) > 100 {
			max := 50
			var divided [][]string

			chunkSize := (len(permstoTest) + max - 1) / max

			for i := 0; i < len(permstoTest); i += chunkSize {
				end := i + chunkSize

				if end > len(permstoTest) {
					end = len(permstoTest)
				}

				divided = append(divided, permstoTest[i:end])
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, kk := range divided {

				ciamResp, err := crmService.Organizations.TestIamPermissions(fmt.Sprintf("organizations/%s", res[1]), &crmv1.TestIamPermissionsRequest{
					Permissions: kk,
				}).Do()
				if err != nil {
					glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

					err := handleError(err)
					if err != nil {
						glog.Fatal(err)
					}
					return err
				}
				for _, p := range ciamResp.Permissions {
					glog.V(2).Infof("     %s\n", p)
				}
			}
		}
	}

	// 	//cloudresourcemanager.googleapis.com/projects/project-id
	re = regexp.MustCompile(resourceManagerProjectsRegex)
	res = re.FindStringSubmatch(checkResource)

	if len(res) == 2 {
		glog.V(2).Infof("==== TestIAMPermissions on Project ====\n")

		var crmService *crmv1.Service

		crmService, err := crmv1.NewService(ctx, option.WithTokenSource(ts), option.WithScopes(cloudPlatformScope))
		if err != nil {
			return err
		}

		if len(permstoTest) > 100 {
			max := 50
			var divided [][]string

			chunkSize := (len(permstoTest) + max - 1) / max

			for i := 0; i < len(permstoTest); i += chunkSize {
				end := i + chunkSize

				if end > len(permstoTest) {
					end = len(permstoTest)
				}

				divided = append(divided, permstoTest[i:end])
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, kk := range divided {

				ciamResp, err := crmService.Projects.TestIamPermissions(res[1], &crmv1.TestIamPermissionsRequest{
					Permissions: kk,
				}).Do()
				if err != nil {
					glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

					err := handleError(err)
					if err != nil {
						glog.Fatal(err)
					}
					return err
				}
				for _, p := range ciamResp.Permissions {
					glog.V(2).Infof("     %s\n", p)
				}
			}
		}
	}
	return nil
}
