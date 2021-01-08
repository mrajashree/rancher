package restrictedadminrbac

import (
	"github.com/rancher/norman/types/slice"
	"github.com/rancher/rancher/pkg/rbac"
	"k8s.io/client-go/util/retry"

	k8srbac "k8s.io/api/rbac/v1"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"

	"k8s.io/apimachinery/pkg/runtime"
)

const (
	grbByRoleIndex = "management.cattle.io/grb-by-role"
)

func (r *rbaccontroller) clusterRBACSync(key string, cluster *v3.Cluster) (runtime.Object, error) {
	if cluster == nil || cluster.DeletionTimestamp != nil {
		return nil, nil
	}

	if cluster.Name == "local" {
		return nil, nil
	}

	grbs, err := r.grbIndexer.ByIndex(grbByRoleIndex, rbac.GlobalRestrictedAdmin)
	if err != nil {
		return nil, err
	}

	var subjects []k8srbac.Subject
	for _, x := range grbs {
		grb, _ := x.(*v3.GlobalRoleBinding)
		restrictedAdminUserName := grb.UserName
		subjects = append(subjects, k8srbac.Subject{
			Kind: "User",
			Name: restrictedAdminUserName,
		})
	}
	_, err = r.roleBindings.Create(&k8srbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rbac.RestrictedAdminMgmtRoleBinding,
			Namespace: cluster.Name,
		},
		Subjects: subjects,
		RoleRef: k8srbac.RoleRef{
			Name: rbac.ManagementCRDsClusterRole,
			Kind: "ClusterRole",
		},
	})
	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return nil, err
	}

	return nil, r.addClusterToRestrictedAdminCR(cluster)
}

func (r *rbaccontroller) addClusterToRestrictedAdminCR(cluster *v3.Cluster) error {
	cr, err := r.crLister.Get("", rbac.RestrictedAdminCRForClusters)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return err
		}
		cr := k8srbac.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: rbac.RestrictedAdminCRForClusters,
			},
			Rules: []k8srbac.PolicyRule{
				{
					APIGroups:     []string{"management.cattle.io"},
					Resources:     []string{"clusters"},
					ResourceNames: []string{cluster.Name},
					Verbs:         []string{"*"},
				},
			},
		}
		_, err := r.clusterRoles.Create(&cr)
		return err
	}

	clusters := cr.Rules[0].ResourceNames
	if slice.ContainsString(clusters, cluster.Name) {
		return nil
	}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crToUpdate, updateErr := r.clusterRoles.Get(rbac.RestrictedAdminCRForClusters, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		clusters := crToUpdate.Rules[0].ResourceNames
		if slice.ContainsString(clusters, cluster.Name) {
			return nil
		}
		crToUpdate.Rules[0].ResourceNames = append(crToUpdate.Rules[0].ResourceNames, cluster.Name)
		_, err := r.clusterRoles.Update(crToUpdate)
		return err
	})
	return err
}
