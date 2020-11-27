package restrictedadminrbac

import (
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/rbac"
	k8srbac "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (r *rbaccontroller) projectRBACSync(key string, project *apimgmtv3.Project) (runtime.Object, error) {
	if project == nil || project.DeletionTimestamp != nil {
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
			Name:      rbac.RestrictedAdminProjectRoleBinding,
			Namespace: project.Name,
		},
		Subjects: subjects,
		RoleRef: k8srbac.RoleRef{
			Name: rbac.ProjectCRDsClusterRole,
			Kind: "ClusterRole",
		},
	})

	if err != nil && !k8serrors.IsAlreadyExists(err) {
		return nil, err
	}
	return nil, nil
}
