package restrictedadminrbac

import (
	"context"

	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	v1 "github.com/rancher/rancher/pkg/generated/norman/rbac.authorization.k8s.io/v1"
	"github.com/rancher/rancher/pkg/types/config"
	"k8s.io/client-go/tools/cache"
)

type rbaccontroller struct {
	grbLister    v3.GlobalRoleBindingLister
	grbIndexer   cache.Indexer
	roleBindings v1.RoleBindingInterface
	clusters     v3.ClusterInterface
	projects     v3.ProjectInterface
	clusterRoles v1.ClusterRoleInterface
	crLister     v1.ClusterRoleLister
}

func Register(ctx context.Context, management *config.ManagementContext) {

	informer := management.Management.GlobalRoleBindings("").Controller().Informer()
	r := rbaccontroller{
		clusters:     management.Management.Clusters(""),
		projects:     management.Management.Projects(""),
		grbLister:    management.Management.GlobalRoleBindings("").Controller().Lister(),
		grbIndexer:   informer.GetIndexer(),
		roleBindings: management.RBAC.RoleBindings(""),
		crLister:     management.RBAC.ClusterRoles("").Controller().Lister(),
		clusterRoles: management.RBAC.ClusterRoles(""),
	}

	r.clusters.AddHandler(ctx, "restrictedAdminsRBACCluster", r.clusterRBACSync)
	r.projects.AddHandler(ctx, "restrictedAdminsRBACProject", r.projectRBACSync)
}
