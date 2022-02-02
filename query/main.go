package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/time/rate"

	errdetails "google.golang.org/genproto/googleapis/rpc/errdetails"

	"google.golang.org/grpc/status"

	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"

	//"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iap/v1"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/storage/v1"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"

	policytroubleshooter "cloud.google.com/go/policytroubleshooter/apiv1"
	policypb "google.golang.org/genproto/googleapis/cloud/policytroubleshooter/v1"

	storageAPI "cloud.google.com/go/storage"
)

const (
	bigqueryTablesRegex              = "//bigquery.googleapis.com/projects/(.+)/datasets/(.+)/tables/(.+)"
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
)

var (
	scope                     = flag.String("scope", "", "Scope to check")
	checkResource             = flag.String("checkResource", "", "Resource to check")
	identity                  = flag.String("identity", "", "Permission to check")
	impersonateServiceAccount = flag.String("impersonateServiceAccount", "", "ServiceAccount to impersonate")
	useIAMPolicyRequest       = flag.Bool("useIAMPolicyRequest", false, "Use IAMPolicy API request (requires admin)")
	projectID                 = flag.String("projectID", "", "ProjectID for quota")

	usePolicyTroubleshooter              = flag.Bool("usePolicyTroubleshooter", false, "Use policytroubleshooter API to check a given permission (requires admin)")
	permissionToCheck                    = flag.String("permissionToCheck", "storage.objects.get", "Permission to check using policytroubleshooter API (requires admin)")
	enableImpersonatedCheck              = flag.Bool("enableImpersonatedCheck", false, "Check for Impersonated credentials (default: false)")
	gcsDestinationForLongRunningAnalysis = flag.String("gcsDestinationForLongRunningAnalysis", "", "Destination gcs bucket to write LongRunningAnalysis (in format ggs://fabled-ray-104117-bucket)")
	limiter                              *rate.Limiter
)

func init() {
}

func main() {
	flag.Parse()

	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		glog.Fatal(err)
	}
	ors := iam.NewPermissionsService(iamService)

	s := []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/cloud-platform"}

	var ts oauth2.TokenSource

	if *impersonateServiceAccount != "" {
		ts, err = impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: *impersonateServiceAccount,
			Scopes:          s,
		})
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			return
		}
	} else {
		ts, err = google.DefaultTokenSource(ctx)
		if err != nil {
			glog.Errorf("Unable to create Impersonated TokenSource %v ", err)
			return
		}
	}

	// ***************************************************************************************************

	if *useIAMPolicyRequest {

		glog.V(2).Infof("Getting AnalyzeIamPolicyRequest")
		creds, err := google.FindDefaultCredentials(ctx)
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
		// https://cloud.google.com/asset-inventory/docs/resource-name-format
		// https://cloud.google.com/asset-inventory/docs/supported-asset-types#analyzable_asset_types

		if *enableImpersonatedCheck == false {
			req := &assetpb.AnalyzeIamPolicyRequest{
				AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
					Scope: *scope,
					ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
						FullResourceName: *checkResource,
					},
					IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
						Identity: fmt.Sprintf("%s", *identity),
					},
					Options: &assetpb.IamPolicyAnalysisQuery_Options{
						ExpandGroups:                       true,
						OutputGroupEdges:                   true,
						ExpandResources:                    true,
						ExpandRoles:                        true,
						OutputResourceEdges:                true,
						AnalyzeServiceAccountImpersonation: *enableImpersonatedCheck, // NOTE, this is verrry expensive, only enable this if necessary.  TODO: use longrunning
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
					glog.V(2).Infof("        through %s", acl.Accesses)

				}
				if result.AttachedResourceFullName == *checkResource {
					glog.V(2).Info("          which is applied to the resource directly")
				} else {
					for _, a := range result.AccessControlLists {
						glog.V(2).Info("          which is inherited through resource ancestry ", getResourceAncestry(a.ResourceEdges, *checkResource, []string{*checkResource}))
					}
				}
				if stringInSlice(*identity, result.IamBinding.Members) {
					glog.V(2).Info("          and the user is directly included in the role binding directly")
				} else {
					glog.V(2).Info("          and the user is included in the role binding through a group hierarchy: ", getIdentityAncestry(result.IdentityList, *identity, []string{*identity}))
				}
			}
			if len(resp.MainAnalysis.AnalysisResults) == 0 {
				glog.V(2).Infof("      %s does not access to resource %s", *identity, *checkResource)
			}
		} else {

			fileName := fmt.Sprintf("%s", time.Now().UTC().Format("20060102150405"))
			req := &assetpb.AnalyzeIamPolicyLongrunningRequest{
				AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
					Scope: *scope,
					ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
						FullResourceName: *checkResource,
					},
					IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
						Identity: fmt.Sprintf("%s", *identity),
					},
					Options: &assetpb.IamPolicyAnalysisQuery_Options{
						ExpandGroups:                       true,
						OutputGroupEdges:                   true,
						ExpandResources:                    true,
						ExpandRoles:                        true,
						OutputResourceEdges:                true,
						AnalyzeServiceAccountImpersonation: *enableImpersonatedCheck, // NOTE, this is verrry expensive, only enable this if necessary.  TODO: use longrunning
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

		glog.V(20).Infof("   User's AccessState %s\n", resp.Access)

		for _, r := range resp.ExplainedPolicies {
			if r.Access == policypb.AccessState_GRANTED {
				glog.V(20).Infof("   User's AccessState granted at %s\n", r.FullResourceName)
				// for _, b := range r.Policy.Bindings {
				// 	glog.V(20).Infof("       which has roles %s\n", b.Role)
				// }
				for _, be := range r.BindingExplanations {
					if be.Access == policypb.AccessState_GRANTED {
						glog.V(20).Infof("   within which the user has binding with permission via roles %s\n", be.Role)
						glog.V(20).Infof("   through membership %s\n", be.Memberships)
					}
				}
			}
		}
		//glog.V(20).Infof("================ Getting PolicyTroubleshooter %v\n", resp)

	} else {

		glog.V(2).Infof("================ QueryTestablePermissions with Resource ======================\n")
		if *scope == "" || *checkResource == "" {
			glog.Error("Must specify scope,checkResource")
			return
		}
		var permstoTest []string
		perms := make([]*iam.Permission, 0)
		nextPageToken := ""
		for {
			ps, err := ors.QueryTestablePermissions(&iam.QueryTestablePermissionsRequest{
				FullResourceName: *checkResource,
				PageToken:        nextPageToken,
			}).Do()
			if err != nil {
				glog.Fatal(err)
			}
			glog.V(20).Infof("================ Getting Permissions %v\n", ps.NextPageToken)

			for _, sa := range ps.Permissions {
				glog.V(20).Infof("            Adding Permission to check %s\n", sa.Name)
				perms = append(perms, sa)
			}

			nextPageToken = ps.NextPageToken
			if nextPageToken == "" {
				break
			}

		}

		glog.V(2).Infof("Testable permissions on resource:\n")
		for _, p := range perms {
			glog.V(10).Infof("     %s\n", p.Name)
			permstoTest = append(permstoTest, p.Name)
		}

		// ***************************************************************************************************

		var res []string

		// 	//bigquery.googleapis.com/projects/project-id/datasets/dataset-id
		re := regexp.MustCompile(bigqueryTablesRegex)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 4 {
			glog.V(2).Infof("==== TestIAMPermissions as BigQuery Tables Resource ====\n")
			var bigQueryService *bigquery.Service

			bigQueryService, err = bigquery.NewService(ctx, option.WithTokenSource(ts))
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		// 	//iam.googleapis.com/projects/project-id/serviceAccounts/service-account-email

		re = regexp.MustCompile(iamServiceAccountsRegex)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 3 {
			glog.V(2).Infof("==== TestIAMPermissions as ServiceAccounts Resource ====\n")
			var iamService *iam.Service

			iamService, err = iam.NewService(ctx, option.WithTokenSource(ts))
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		//	//iam.googleapis.com/projects/project-id/serviceAccounts/service-account-email/keys/key-id

		re = regexp.MustCompile(serviceAccountsKeysRegex)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 4 {
			glog.Error("Unimplemented")
			return
			// glog.V(2).Infof("==== TestIAMPermissions as ServiceAccountsKeys Resource ====\n")
			// var iamService *iam.Service

			// iamService, err = iam.NewService(ctx)
			// if err != nil {
			// 	glog.Fatal(err)
			// }

			// ciamResp, err := iamService.Projects.ServiceAccounts.TestIamPermissions(fmt.Sprintf("projects/%s/serviceAccounts/%s/keys/%s", res[1], res[2], res[3]), &iam.TestIamPermissionsRequest{
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

		//	//iap.googleapis.com/projects/project-number/iap_web/appengine-project-id/services/app-service-id

		re = regexp.MustCompile(iapAppEngineRegex)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 4 {

			glog.V(2).Infof("==== TestIAMPermissions as IAP AppEngine Resource ==== %s\n", res[2])
			var iapService *iap.Service

			iapService, err = iap.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}

		}

		//	//iap.googleapis.com/projects/project-number/iap_web/compute/services/backend-service-id

		re = regexp.MustCompile(iapGCERegex)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 3 {
			glog.V(2).Infof("==== TestIAMPermissions as IAP ComputeEngine Resource ====\n")
			var iapService *iap.Service

			iapService, err = iap.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		//	//spanner.googleapis.com/projects/project-id/instances/instance-id

		re = regexp.MustCompile(spannerInstances)
		res = re.FindStringSubmatch(*checkResource)
		if len(res) == 3 {
			glog.V(2).Infof("==== TestIAMPermissions as Spanner Resource ====\n")
			var spannerService *spanner.Service

			spannerService, err = spanner.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		// 	//storage.googleapis.com/projects/_/buckets/bucket-id
		re = regexp.MustCompile(storageBucketsRegex)
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 2 {

			glog.V(2).Infof("==== TestIAMPermissions as GCS Bucket Resource ====\n")

			var storageService *storage.Service

			storageService, err = storage.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				"resourcemanager.hierarchyNodes.listTagBindings"})

			ciamResp, err := storageService.Buckets.TestIamPermissions(res[1], permstoTest).Do()
			if err != nil {
				glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

				err := handleError(err)
				if err != nil {
					glog.Fatal(err)
				}
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		// 	//compute.googleapis.com/projects/project-id/zones/zone/instances/instance-id
		re = regexp.MustCompile(computeInstanceRegex)
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 4 {

			glog.V(2).Infof("==== TestIAMPermissions as Compute Instance Resource ====\n")

			var computeService *compute.Service

			computeService, err = compute.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		// 	//compute.googleapis.com/projects/project-id/global/networks/network
		re = regexp.MustCompile(computeNetworksRegex)
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 3 {

			glog.V(2).Infof("==== TestIAMPermissions as Compute Network Resource ====\n")
			glog.Error("Unimplemented")
			return

			// var computeService *compute.Service

			// computeService, err = compute.NewService(ctx)
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
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 4 {

			glog.V(2).Infof("==== TestIAMPermissions as Compute SubNetwork Resource ====\n")

			var computeService *compute.Service

			computeService, err = compute.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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
				return
			}
			glog.V(2).Infof(" User permission  on resource: \n")
			for _, p := range ciamResp.Permissions {
				glog.V(2).Infof("     %s\n", p)
			}
		}

		// //container.googleapis.com/projects/project-id/clusters/cluster-id
		re = regexp.MustCompile(kubernetesEngineRegex)
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 3 {
			glog.V(2).Infof("==== TestIAMPermissions on Kubernetes Engine Resource ====\n")
			glog.Error("Unimplemented")
			return

			// var containerService *container.Service

			// containerService, err = container.NewService(ctx)
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
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 2 {
			glog.V(2).Infof("==== TestIAMPermissions on Organizations ====\n")

			var crmService *cloudresourcemanager.Service

			crmService, err = cloudresourcemanager.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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

					ciamResp, err := crmService.Organizations.TestIamPermissions(fmt.Sprintf("organizations/%s", res[1]), &cloudresourcemanager.TestIamPermissionsRequest{
						Permissions: kk,
					}).Do()
					if err != nil {
						glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

						err := handleError(err)
						if err != nil {
							glog.Fatal(err)
						}
						return
					}
					for _, p := range ciamResp.Permissions {
						glog.V(2).Infof("     %s\n", p)
					}
				}
			}
		}

		// 	//cloudresourcemanager.googleapis.com/projects/project-id
		re = regexp.MustCompile(resourceManagerProjectsRegex)
		res = re.FindStringSubmatch(*checkResource)

		if len(res) == 2 {
			glog.V(2).Infof("==== TestIAMPermissions on Project ====\n")

			var crmService *cloudresourcemanager.Service

			crmService, err = cloudresourcemanager.NewService(ctx)
			if err != nil {
				glog.Fatal(err)
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

					ciamResp, err := crmService.Projects.TestIamPermissions(res[1], &cloudresourcemanager.TestIamPermissionsRequest{
						Permissions: kk,
					}).Do()
					if err != nil {
						glog.V(2).Infof("      Error getting IAM Permissions: %s\n", err)

						err := handleError(err)
						if err != nil {
							glog.Fatal(err)
						}
						return
					}
					for _, p := range ciamResp.Permissions {
						glog.V(2).Infof("     %s\n", p)
					}
				}
			}
		}
	}

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
	if ee, ok := err.(*googleapi.Error); ok {
		if ee.Code == 404 {
			glog.V(4).Infof("            Ignoring 404 Error for  %v", ee)
		} else {
			glog.Infof("%v", ee.Details)
		}
	}

	if s, ok := status.FromError(err); ok {
		for _, d := range s.Proto().Details {

			glog.V(2).Infof("%s\n", d.TypeUrl)
			// https://github.com/googleapis/googleapis/blob/master/google/rpc/error_details.proto
			switch d.TypeUrl {
			case "type.googleapis.com/google.rpc.Help":
				h := &errdetails.Help{}
				err = ptypes.UnmarshalAny(d, h)
				if err != nil {
					return err
				}
				for _, l := range h.Links {
					glog.Errorf("   ErrorHelp Description %v\n", l.Description)
				}
			case "type.googleapis.com/google.rpc.ErrorInfo":
				h := &errdetails.ErrorInfo{}
				err = ptypes.UnmarshalAny(d, h)
				if err != nil {
					return err
				}
				glog.Errorf("  ErrorInfo: %v\n", h)
			case "type.googleapis.com/google.rpc.QuotaFailure":
				h := &errdetails.QuotaFailure{}
				err = ptypes.UnmarshalAny(d, h)
				if err != nil {
					return err
				}
				glog.Errorf("  QuotaFailure.Violations: %v\n", h.Violations)
			case "type.googleapis.com/google.rpc.DebugInfo":
				h := &errdetails.DebugInfo{}
				err = ptypes.UnmarshalAny(d, h)
				if err != nil {
					return err
				}
				glog.Errorf("  DebugInfo: %v\n", h.Detail)

			default:
				glog.Errorf("Don't know type %T\n", d.TypeUrl)
			}
		}
	}
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

func getResourceAncestry(ed []*assetpb.IamPolicyAnalysisResult_Edge, target string, curr []string) []string {
	for _, l := range ed {
		if l.TargetNode == target {
			return getResourceAncestry(ed, l.SourceNode, append(curr, fmt.Sprintf(" --> %s ", l.SourceNode)))
		}
	}
	return curr
}

func recurseDelegationForResource(lidentity, lresource string, resp assetpb.AnalyzeIamPolicyResponse) {
	for _, result := range resp.ServiceAccountImpersonationAnalysis {
		for _, r := range result.AnalysisResults {
			for _, n := range r.IdentityList.Identities {
				if n.Name == lidentity {
					if r.AttachedResourceFullName == lresource {
						glog.V(2).Infof("          %s has iam permissions %s  on %s", lidentity, r.IamBinding.Role, r.AttachedResourceFullName)
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
	return
}
