package main

import (
	"context"
	"flag"
	"fmt"
	"regexp"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/golang/glog"
	"golang.org/x/time/rate"

	"github.com/golang/protobuf/ptypes"
	errdetails "google.golang.org/genproto/googleapis/rpc/errdetails"

	"google.golang.org/grpc/status"

	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"

	//"google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iap/v1"
	"google.golang.org/api/spanner/v1"
	"google.golang.org/api/storage/v1"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
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
	scope         = flag.String("scope", "", "Scope to check")
	checkResource = flag.String("checkResource", "", "Resource to check")
	identity      = flag.String("identity", "", "Permission to check")

	useIAMPolicyRequest = flag.Bool("useIAMPolicyRequest", false, "Use IAMPolicy API request (requires admin)")

	limiter *rate.Limiter
)

func init() {
}

func main() {
	flag.Parse()

	if *scope == "" || *checkResource == "" || *identity == "" {
		glog.Error("Must specify scope,checkResource,identity")
		return
	}

	ctx := context.Background()

	iamService, err := iam.NewService(ctx)
	if err != nil {
		glog.Fatal(err)
	}
	ors := iam.NewPermissionsService(iamService)

	glog.V(2).Infof("================ QueryTestablePermissions with Resource ======================\n")

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

	glog.V(2).Infof("Testable permissions on resource: (set -v 10 to view):\n")
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

		bigQueryService, err = bigquery.NewService(ctx)
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

		iamService, err = iam.NewService(ctx)
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

		permstoTest = remove(permstoTest, []string{
			"storage.objects.getIamPolicy",
			"storage.objects.setIamPolicy",
			"resourcemanager.resourceTagBindings.create",
			"resourcemanager.resourceTagBindings.delete",
			"resourcemanager.resourceTagBindings.list"})

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

	if *useIAMPolicyRequest {

		glog.V(2).Infof("Getting AnalyzeIamPolicyRequest")
		assetClient, err := asset.NewClient(ctx)
		if err != nil {
			glog.Fatal(err)
		}
		// https://cloud.google.com/asset-inventory/docs/resource-name-format
		// https://cloud.google.com/asset-inventory/docs/supported-asset-types#analyzable_asset_types

		req := &assetpb.AnalyzeIamPolicyRequest{
			AnalysisQuery: &assetpb.IamPolicyAnalysisQuery{
				Scope: *scope,
				ResourceSelector: &assetpb.IamPolicyAnalysisQuery_ResourceSelector{
					FullResourceName: *checkResource,
				},
				IdentitySelector: &assetpb.IamPolicyAnalysisQuery_IdentitySelector{
					// TODO: support serviceAccount:, group: and principal:
					Identity: fmt.Sprintf("user:%s", *identity),
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
				glog.V(2).Infof("    AnalysisResults.Resources %s", acl.Resources)
				glog.V(2).Infof("    AnalysisResults.Accesses %s", acl.Accesses)
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
