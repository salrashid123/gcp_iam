package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/golang/glog"
	"golang.org/x/time/rate"
	"google.golang.org/api/cloudresourcemanager/v1"

	"google.golang.org/api/iam/v1"
	//asset "cloud.google.com/go/asset/apiv1"
	//assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

// go run main.go -v 20 -alsologtostderr

type Roles struct {
	Roles []Role `json:"roles"`
}

type Role struct {
	Name                string   `json:"name"`
	Role                iam.Role `json:"role"`
	IncludedPermissions []string `json:"included_permissions"`
}

type Permissions struct {
	Permissions []Permission `json:"permissions"`
}

type Permission struct {
	//Permission iam.Permission // there's no direct way to query a given permission detail!
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

const (
	projectNumber                = "248066739582"
	maxRequestsPerSecond float64 = 4 // "golang.org/x/time/rate" limiter to throttle operations
	burst                int     = 4
)

var (
	cmutex    = &sync.Mutex{}
	pmutex    = &sync.Mutex{}
	projectID = flag.String("projectID", "fabled-ray-104117", "GCP ProjetID")

	organization    = flag.String("organization", "", "OrganizationID")
	checkPermission = flag.String("checkPermission", "compute.instances.get", "Permission to check")
	checkResource   = flag.String("checkResource", "projects/fabled-ray-104117/zones/us-central1-a/instances/external", "Permission to check")
	projects        = make([]*cloudresourcemanager.Project, 0)

	permissions = &Permissions{}
	roles       = &Roles{}

	limiter *rate.Limiter
	ors     *iam.RolesService
)

func init() {
}

func main() {
	flag.Parse()

	ctx := context.Background()
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		glog.Fatal(err)
	}

	iamService, err := iam.NewService(ctx)
	if err != nil {
		glog.Fatal(err)
	}
	ors = iam.NewRolesService(iamService)

	limiter = rate.NewLimiter(rate.Limit(maxRequestsPerSecond), burst)

	glog.V(2).Infof("Getting Organization Roles/Permissions")

	if *organization == "" {
		glog.Error(errors.New("--organization value must be set"))
		return
	}
	oreq, err := crmService.Organizations.Get(fmt.Sprintf("organizations/%s", *organization)).Do()
	if err != nil {
		glog.Fatal(err)
	}
	glog.V(2).Infof("     Organization Name %s", oreq.Name)
	*organization = oreq.Name

	parent := fmt.Sprintf(*organization)
	err = generateMap(ctx, parent, "permissions_organization.json", "roles_organization.json")
	if err != nil {
		glog.Fatal(err)
	}

	glog.V(2).Infof("Getting Project Roles/Permissions")
	// TODO: only get projects in the selected organization
	preq := crmService.Projects.List()
	if err := preq.Pages(ctx, func(page *cloudresourcemanager.ListProjectsResponse) error {
		for _, p := range page.Projects {
			if p.LifecycleState == "ACTIVE" {
				projects = append(projects, p)
			}
		}
		return nil
	}); err != nil {
		glog.Fatal(err)
	}
	for _, p := range projects {
		parent := fmt.Sprintf("projects/%s", p.ProjectId)
		err = generateMap(ctx, parent, "permissions_"+p.ProjectId+".json", "roles_"+p.ProjectId+".json")
		if err != nil {
			glog.Fatal(err)
		}
	}

	glog.V(2).Infof("Getting Default Roles/Permissions")
	parent = ""
	err = generateMap(ctx, parent, "permissions_default.json", "roles_default.json")
	if err != nil {
		glog.Fatal(err)
	}

	glog.V(2).Infof("done")
}

func generateMap(ctx context.Context, parent, permissionFileName, rolesFileName string) error {
	var wg sync.WaitGroup

	oireq := ors.List().Parent(parent)
	if err := oireq.Pages(ctx, func(page *iam.ListRolesResponse) error {
		for _, sa := range page.Roles {
			wg.Add(1)
			go func(ctx context.Context, wg *sync.WaitGroup, sa *iam.Role) {
				glog.V(20).Infof("%s\n", sa.Name)
				defer wg.Done()
				var err error
				if err := limiter.Wait(ctx); err != nil {
					glog.Fatal(err)
				}
				if ctx.Err() != nil {
					glog.Fatal(err)
				}
				rc, err := ors.Get(sa.Name).Do()
				if err != nil {
					glog.Fatal(err)
				}
				cr := &Role{
					Name:                sa.Name,
					Role:                *sa,
					IncludedPermissions: rc.IncludedPermissions,
				}
				cmutex.Lock()
				_, ok := findRoles(roles.Roles, sa.Name)
				if !ok {
					glog.V(2).Infof("     Iterating Role  %s", sa.Name)
					roles.Roles = append(roles.Roles, *cr)
				}
				cmutex.Unlock()

				for _, perm := range rc.IncludedPermissions {
					glog.V(2).Infof("     Appending Permission %s to Role %s", perm, sa.Name)
					i, ok := findPermission(permissions.Permissions, perm)

					if !ok {
						pmutex.Lock()
						permissions.Permissions = append(permissions.Permissions, Permission{
							Name:  perm,
							Roles: []string{sa.Name},
						})
						pmutex.Unlock()
					} else {
						pmutex.Lock()
						p := permissions.Permissions[i]
						_, ok := find(p.Roles, sa.Name)
						if !ok {
							p.Roles = append(p.Roles, sa.Name)
							permissions.Permissions[i] = p
						}
						pmutex.Unlock()
					}

				}
			}(ctx, &wg, sa)

		}
		return nil
	}); err != nil {
		return err
	}

	wg.Wait()
	var prettyJSON bytes.Buffer
	buf, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	err = json.Indent(&prettyJSON, buf, "", "\t")
	if err != nil {
		return err
	}
	//glog.V(20).Infof("    Role %s\n", string(prettyJSON.Bytes()))
	buf, err = json.Marshal(permissions)
	if err != nil {
		return err
	}
	err = json.Indent(&prettyJSON, buf, "", "\t")
	if err != nil {
		return err
	}
	//glog.V(20).Infof("    Permissions %s\n", string(prettyJSON.Bytes()))

	pfile, _ := json.MarshalIndent(permissions, "", " ")

	err = ioutil.WriteFile(permissionFileName, pfile, 0644)
	if err != nil {
		return err
	}

	rfile, _ := json.MarshalIndent(roles, "", " ")

	err = ioutil.WriteFile(rolesFileName, rfile, 0644)
	if err != nil {
		return err
	}
	return nil

}

func find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func findRoles(slice []Role, val string) (int, bool) {
	for i, item := range slice {
		if item.Name == val {
			return i, true
		}
	}
	return -1, false
}

func findPermission(slice []Permission, val string) (int, bool) {
	for i, item := range slice {
		if item.Name == val {
			return i, true
		}
	}
	return -1, false
}