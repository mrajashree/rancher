package auth

import (
	"fmt"
	"reflect"

	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types/slice"
	"github.com/rancher/rancher/pkg/clustermanager"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	rbacv1 "github.com/rancher/rancher/pkg/generated/norman/rbac.authorization.k8s.io/v1"
	"github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/rbac"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
)

var (
	globalRoleBindingLabel = map[string]string{"authz.management.cattle.io/globalrolebinding": "true"}
)

const (
	catalogTemplateResourceRule        = "catalogtemplates"
	catalogTemplateVersionResourceRule = "catalogtemplateversions"
	crbNameAnnotation                  = "authz.management.cattle.io/crb-name"
	crbNamePrefix                      = "cattle-globalrolebinding-"
	globalCatalogRole                  = "global-catalog"
	globalCatalogRoleBinding           = "global-catalog-binding"
	grbController                      = "mgmt-auth-grb-controller"
	templateResourceRule               = "templates"
	templateVersionResourceRule        = "templateversions"
)

func newGlobalRoleBindingLifecycle(management *config.ManagementContext, clusterManager *clustermanager.Manager) *globalRoleBindingLifecycle {
	return &globalRoleBindingLifecycle{
		clusters:          management.Management.Clusters(""),
		clusterLister:     management.Management.Clusters("").Controller().Lister(),
		projectLister:     management.Management.Projects("").Controller().Lister(),
		clusterManager:    clusterManager,
		clusterRoles:      management.RBAC.ClusterRoles(""),
		crbClient:         management.RBAC.ClusterRoleBindings(""),
		crbLister:         management.RBAC.ClusterRoleBindings("").Controller().Lister(),
		grLister:          management.Management.GlobalRoles("").Controller().Lister(),
		roles:             management.RBAC.Roles(""),
		roleLister:        management.RBAC.Roles("").Controller().Lister(),
		roleBindings:      management.RBAC.RoleBindings(""),
		roleBindingLister: management.RBAC.RoleBindings("").Controller().Lister(),
	}
}

type globalRoleBindingLifecycle struct {
	clusters          v3.ClusterInterface
	clusterLister     v3.ClusterLister
	projectLister     v3.ProjectLister
	clusterManager    *clustermanager.Manager
	clusterRoles      rbacv1.ClusterRoleInterface
	crbClient         rbacv1.ClusterRoleBindingInterface
	crbLister         rbacv1.ClusterRoleBindingLister
	grLister          v3.GlobalRoleLister
	roles             rbacv1.RoleInterface
	roleLister        rbacv1.RoleLister
	roleBindings      rbacv1.RoleBindingInterface
	roleBindingLister rbacv1.RoleBindingLister
}

func (grb *globalRoleBindingLifecycle) Create(obj *v3.GlobalRoleBinding) (runtime.Object, error) {
	err := grb.reconcileGlobalRoleBinding(obj)
	return obj, err
}

func (grb *globalRoleBindingLifecycle) Updated(obj *v3.GlobalRoleBinding) (runtime.Object, error) {
	err := grb.reconcileGlobalRoleBinding(obj)
	return obj, err
}

func (grb *globalRoleBindingLifecycle) Remove(obj *v3.GlobalRoleBinding) (runtime.Object, error) {
	if obj.GlobalRoleName == rbac.GlobalAdmin || obj.GlobalRoleName == rbac.GlobalRestrictedAdmin {
		return obj, grb.deleteAdminBinding(obj)
	}
	// Don't need to delete the created ClusterRole because owner reference will take care of that
	if obj.GlobalRoleName == rbac.GlobalRestrictedAdmin {
		// remove restricted admin from the RB/CRB subjects list

	}
	return obj, nil
}

func (grb *globalRoleBindingLifecycle) deleteAdminBinding(obj *v3.GlobalRoleBinding) error {
	// Explicit API call to ensure we have the most recent cluster info when deleting admin bindings
	clusters, err := grb.clusters.List(metav1.ListOptions{})
	if err != nil {
		return err
	}

	// Collect all the errors to delete as many user context bindings as possible
	var allErrors []error

	for _, cluster := range clusters.Items {
		userContext, err := grb.clusterManager.UserContext(cluster.Name)
		if err != nil {
			// ClusterUnavailable error indicates the record can't talk to the downstream cluster
			if !IsClusterUnavailable(err) {
				allErrors = append(allErrors, err)
			}
			continue
		}

		bindingName := rbac.GrbCRBName(obj)
		b, err := userContext.RBAC.ClusterRoleBindings("").Controller().Lister().Get("", bindingName)
		if err != nil {
			// User context clusterRoleBinding doesn't exist
			if !apierrors.IsNotFound(err) {
				allErrors = append(allErrors, err)
			}
			continue
		}

		err = userContext.RBAC.ClusterRoleBindings("").Delete(b.Name, &metav1.DeleteOptions{})
		if err != nil {
			// User context clusterRoleBinding doesn't exist
			if !apierrors.IsNotFound(err) {
				allErrors = append(allErrors, err)
			}
			continue
		}

	}

	if len(allErrors) > 0 {
		return fmt.Errorf("errors deleting admin global role binding: %v", allErrors)
	}
	return nil
}

func (grb *globalRoleBindingLifecycle) reconcileGlobalRoleBinding(globalRoleBinding *v3.GlobalRoleBinding) error {
	crbName, ok := globalRoleBinding.Annotations[crbNameAnnotation]
	if !ok {
		crbName = crbNamePrefix + globalRoleBinding.Name
	}

	subject := rbac.GetGRBSubject(globalRoleBinding)
	if globalRoleBinding.GlobalRoleName == rbac.GlobalRestrictedAdmin {
		if err := grb.syncDownstreamClusterPermissions(subject); err != nil {
			return err
		}
	}

	crb, _ := grb.crbLister.Get("", crbName)
	if crb != nil {
		subjects := []v1.Subject{subject}
		updateSubject := !reflect.DeepEqual(subjects, crb.Subjects)

		updateRoleRef := false
		var roleRef v1.RoleRef
		gr, _ := grb.grLister.Get("", globalRoleBinding.GlobalRoleName)
		if gr != nil {
			crNameFromGR := getCRName(gr)
			if crNameFromGR != crb.RoleRef.Name {
				updateRoleRef = true
				roleRef = v1.RoleRef{
					Name: crNameFromGR,
					Kind: clusterRoleKind,
				}
			}
		}
		if updateSubject || updateRoleRef {
			crb = crb.DeepCopy()
			if updateRoleRef {
				crb.RoleRef = roleRef
			}
			crb.Subjects = subjects
			logrus.Infof("[%v] Updating clusterRoleBinding %v for globalRoleBinding %v user %v", grbController, crb.Name, globalRoleBinding.Name, globalRoleBinding.UserName)
			if _, err := grb.crbClient.Update(crb); err != nil {
				return errors.Wrapf(err, "couldn't update ClusterRoleBinding %v", crb.Name)
			}
		}
		return grb.addRulesForTemplateAndTemplateVersions(globalRoleBinding, subject)
	}

	logrus.Infof("Creating new GlobalRoleBinding for GlobalRoleBinding %v", globalRoleBinding.Name)
	gr, _ := grb.grLister.Get("", globalRoleBinding.GlobalRoleName)
	var crName string
	if gr != nil {
		crName = getCRName(gr)
	} else {
		crName = generateCRName(globalRoleBinding.GlobalRoleName)
	}
	logrus.Infof("[%v] Creating clusterRoleBinding for globalRoleBinding %v for user %v with role %v", grbController, globalRoleBinding.Name, globalRoleBinding.UserName, crName)
	_, err := grb.crbClient.Create(&v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: crbName,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: globalRoleBinding.TypeMeta.APIVersion,
					Kind:       globalRoleBinding.TypeMeta.Kind,
					Name:       globalRoleBinding.Name,
					UID:        globalRoleBinding.UID,
				},
			},
			Labels: globalRoleBindingLabel,
		},
		Subjects: []v1.Subject{subject},
		RoleRef: v1.RoleRef{
			Name: crName,
			Kind: clusterRoleKind,
		},
	})
	if err != nil {
		return err
	}
	// Add an annotation to the globalrole indicating the name we used for future updates
	if globalRoleBinding.Annotations == nil {
		globalRoleBinding.Annotations = map[string]string{}
	}
	globalRoleBinding.Annotations[crbNameAnnotation] = crbName

	return grb.addRulesForTemplateAndTemplateVersions(globalRoleBinding, subject)
}

func (grb *globalRoleBindingLifecycle) addRulesForTemplateAndTemplateVersions(globalRoleBinding *v3.GlobalRoleBinding, subject v1.Subject) error {
	var catalogTemplateRule, catalogTemplateVersionRule *v1.PolicyRule
	// Check if the current globalRole has rules for templates and templateversions
	gr, err := grb.grLister.Get("", globalRoleBinding.GlobalRoleName)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if gr != nil {
		for _, rule := range gr.Rules {
			for _, resource := range rule.Resources {
				if resource == templateResourceRule {
					if catalogTemplateRule == nil {
						catalogTemplateRule = &v1.PolicyRule{
							APIGroups: rule.APIGroups,
							Resources: []string{catalogTemplateResourceRule},
							Verbs:     rule.Verbs,
						}
					} else {
						for _, v := range rule.Verbs {
							if !slice.ContainsString(catalogTemplateRule.Verbs, v) {
								catalogTemplateRule.Verbs = append(catalogTemplateRule.Verbs, v)
							}
						}
					}
				} else if resource == templateVersionResourceRule {
					if catalogTemplateVersionRule == nil {
						catalogTemplateVersionRule = &v1.PolicyRule{
							APIGroups: rule.APIGroups,
							Resources: []string{catalogTemplateVersionResourceRule},
							Verbs:     rule.Verbs,
						}
					} else {
						for _, v := range rule.Verbs {
							if !slice.ContainsString(catalogTemplateVersionRule.Verbs, v) {
								catalogTemplateVersionRule.Verbs = append(catalogTemplateVersionRule.Verbs, v)
							}
						}
					}
				}
			}
		}
	}
	// If rules for "templates and "templateversions" exists, create a role for the granting access to
	// catalogtemplates and catalogtemplateversions in the global namespace
	var rules []v1.PolicyRule
	if catalogTemplateRule != nil {
		rules = append(rules, *catalogTemplateRule)
	}
	if catalogTemplateVersionRule != nil {
		rules = append(rules, *catalogTemplateVersionRule)
	}
	if len(rules) > 0 {
		_, err := grb.roleLister.Get(namespace.GlobalNamespace, globalCatalogRole)
		if err != nil {
			if apierrors.IsNotFound(err) {
				role := &v1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name:      globalCatalogRole,
						Namespace: namespace.GlobalNamespace,
					},
					Rules: rules,
				}
				_, err = grb.roles.Create(role)
				if err != nil && !apierrors.IsAlreadyExists(err) {
					return err
				}
			} else {
				return err
			}
		}
		// Create a rolebinding, referring the above role, and using globalrole user.Username as the subject
		// Check if rb exists first!
		grbName := globalRoleBinding.UserName + "-" + globalCatalogRoleBinding
		_, err = grb.roleBindingLister.Get(namespace.GlobalNamespace, grbName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				rb := &v1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      grbName,
						Namespace: namespace.GlobalNamespace,
					},
					Subjects: []v1.Subject{subject},
					RoleRef: v1.RoleRef{
						Kind: "Role",
						Name: globalCatalogRole,
					},
				}
				_, err = grb.roleBindings.Create(rb)
				if err != nil && !apierrors.IsAlreadyExists(err) {
					return err
				}
			} else {
				return err
			}
		}
	}
	return nil
}

func (grb *globalRoleBindingLifecycle) syncDownstreamClusterPermissions(subject v1.Subject) error {
	if err := grb.addRestrictedAdminToClustersCRB(subject); err != nil {
		return err
	}

	return grb.grantRestrictedAdminUserClusterPermissions(subject)
}

func (grb *globalRoleBindingLifecycle) addRestrictedAdminToClustersCRB(subject v1.Subject) error {
	// get the CRB for the downstream clusters clusterRole and update its subject list to include this user
	// the CR for downstream clusters contains a Role that has all clusters' names in the ResourceNames field
	crb, err := grb.crbLister.Get("", rbac.RestrictedAdminCRBForClusters)
	if err != nil {
		if apierrors.IsNotFound(err) {
			_, err := grb.crbClient.Create(&v1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: rbac.RestrictedAdminCRBForClusters,
				},
				RoleRef: v1.RoleRef{
					Kind: "ClusterRole",
					Name: rbac.RestrictedAdminCRForClusters,
				},
				Subjects: []v1.Subject{subject},
			})
			return err
		}
		return err
	}

	// CRB exists, so update the subjects list to add the grb
	existingSubjects := crb.Subjects
	for _, sub := range existingSubjects {
		if sub.Name == subject.Name && reflect.DeepEqual(sub, subject) {
			// this subject is already added to the CRB
			return nil
		}
	}

	// add subject to CRB
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crbToUpdate, updateErr := grb.crbClient.Get(rbac.RestrictedAdminCRBForClusters, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		existingSubjects := crbToUpdate.Subjects
		for _, sub := range existingSubjects {
			if sub.Name == subject.Name && reflect.DeepEqual(sub, subject) {
				// this subject is already added to the CRB
				return nil
			}
		}
		crbToUpdate.Subjects = append(crbToUpdate.Subjects, subject)
		_, err := grb.crbClient.Update(crbToUpdate)
		return err
	})
}

func (grb *globalRoleBindingLifecycle) grantRestrictedAdminUserClusterPermissions(subject v1.Subject) error {
	var returnErr error
	clusters, err := grb.clusterLister.List("", labels.NewSelector())
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		if cluster.Name == "local" {
			continue
		}
		rb, err := grb.roleBindingLister.Get(cluster.Name, rbac.RestrictedAdminMgmtRoleBinding)
		if err != nil {
			if apierrors.IsNotFound(err) {
				_, err := grb.roleBindings.Create(&v1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      rbac.RestrictedAdminMgmtRoleBinding,
						Namespace: cluster.Name,
					},
					RoleRef: v1.RoleRef{
						Name: rbac.ManagementCRDsClusterRole,
						Kind: "ClusterRole",
					},
					Subjects: []v1.Subject{subject},
				})
				if err != nil {
					returnErr = multierror.Append(returnErr, err)
					continue
				}
			}
			returnErr = multierror.Append(returnErr, err)
		} else {
			if err := grb.addSubjectToRoleBinding(subject, rb.Subjects, rbac.RestrictedAdminMgmtRoleBinding, cluster.Name); err != nil {
				returnErr = multierror.Append(returnErr, err)
			}
		}

		projects, err := grb.projectLister.List(cluster.Name, labels.NewSelector())
		if err != nil {
			returnErr = multierror.Append(returnErr, err)
			continue
		}

		for _, project := range projects {
			rb, err := grb.roleBindingLister.Get(project.Name, rbac.RestrictedAdminProjectRoleBinding)
			if err != nil {
				if apierrors.IsNotFound(err) {
					_, err := grb.roleBindings.Create(&v1.RoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name:      rbac.RestrictedAdminProjectRoleBinding,
							Namespace: cluster.Name,
						},
						RoleRef: v1.RoleRef{
							Name: rbac.ProjectCRDsClusterRole,
							Kind: "ClusterRole",
						},
						Subjects: []v1.Subject{subject},
					})
					if err != nil {
						returnErr = multierror.Append(returnErr, err)
						continue
					}
				}
				returnErr = multierror.Append(returnErr, err)
			} else {
				if err := grb.addSubjectToRoleBinding(subject, rb.Subjects, rbac.RestrictedAdminProjectRoleBinding, project.Name); err != nil {
					returnErr = multierror.Append(returnErr, err)
				}
			}
		}
	}
	return returnErr
}

func (grb *globalRoleBindingLifecycle) removeRestrictedAdminPermissions(obj *v3.GlobalRoleBinding) error {
	subject := rbac.GetGRBSubject(obj)
	if err := grb.removeRestrictedAdminRBPermissions(subject); err != nil {
		return err
	}
	return grb.removeRestrictedAdminCRBPermissions(subject)
}

func (grb *globalRoleBindingLifecycle) removeRestrictedAdminRBPermissions(subject v1.Subject) error {
	var returnErr error
	clusters, err := grb.clusterLister.List("", labels.NewSelector())
	if err != nil {
		return err
	}
	for _, cluster := range clusters {
		if cluster.Name == "local" {
			continue
		}
		clusterRB, err := grb.roleBindingLister.Get(cluster.Name, rbac.RestrictedAdminMgmtRoleBinding)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				returnErr = multierror.Append(returnErr, err)
			}
			continue
		}
		if err := grb.removeSubjectFromRoleBinding(subject, clusterRB.Subjects, rbac.RestrictedAdminMgmtRoleBinding, cluster.Name); err != nil {
			returnErr = multierror.Append(returnErr, err)
		}

		projects, err := grb.projectLister.List(cluster.Name, labels.NewSelector())
		if err != nil {
			returnErr = multierror.Append(returnErr, err)
			continue
		}

		for _, project := range projects {
			projectRB, err := grb.roleBindingLister.Get(project.Name, rbac.RestrictedAdminProjectRoleBinding)
			if err != nil {
				if !apierrors.IsNotFound(err) {
					returnErr = multierror.Append(returnErr, err)
				}
				continue
			}

			if err := grb.removeSubjectFromRoleBinding(subject, projectRB.Subjects, rbac.RestrictedAdminProjectRoleBinding, project.Name); err != nil {
				returnErr = multierror.Append(returnErr, err)
			}
		}
	}
	return returnErr
}

func (grb *globalRoleBindingLifecycle) removeRestrictedAdminCRBPermissions(subject v1.Subject) error {
	clustersCRB, err := grb.crbLister.Get("", rbac.RestrictedAdminCRBForClusters)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	subjectExists, ind := checkSubjectExists(subject, clustersCRB.Subjects)
	if !subjectExists {
		return nil
	}
	updatedSubjectsList := append(clustersCRB.Subjects[:ind], clustersCRB.Subjects[ind+1:]...)
	// remove subject from CRB
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crbToUpdate, updateErr := grb.crbClient.Get(rbac.RestrictedAdminCRBForClusters, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		crbToUpdate.Subjects = updatedSubjectsList
		_, err := grb.crbClient.Update(crbToUpdate)
		return err
	})
}

func (grb *globalRoleBindingLifecycle) addSubjectToRoleBinding(subject v1.Subject, existingSubjects []v1.Subject, name, ns string) error {
	for _, sub := range existingSubjects {
		// subject was already added
		if sub.Name == subject.Name && reflect.DeepEqual(sub, subject) {
			return nil
		}
	}
	// add subject to RB
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rbToUpdate, updateErr := grb.roleBindings.GetNamespaced(ns, name, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		rbToUpdate.Subjects = append(rbToUpdate.Subjects, subject)
		_, err := grb.roleBindings.Update(rbToUpdate)
		return err
	})
}

func (grb *globalRoleBindingLifecycle) removeSubjectFromRoleBinding(subject v1.Subject, existingSubjects []v1.Subject, name, ns string) error {
	subjectExists, ind := checkSubjectExists(subject, existingSubjects)
	if !subjectExists {
		return nil
	}
	updatedSubjectsList := append(existingSubjects[:ind], existingSubjects[ind+1:]...)

	// remove subject from RB
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		rbToUpdate, updateErr := grb.roleBindings.GetNamespaced(ns, name, metav1.GetOptions{})
		if updateErr != nil {
			return updateErr
		}
		rbToUpdate.Subjects = updatedSubjectsList
		_, err := grb.roleBindings.Update(rbToUpdate)
		return err
	})
}

func checkSubjectExists(subject v1.Subject, existingSubjects []v1.Subject) (bool, int) {
	var subjectExists bool
	var subjectIndex int
	for ind, sub := range existingSubjects {
		// subject was already added
		if sub.Name == subject.Name && reflect.DeepEqual(sub, subject) {
			subjectExists = true
			subjectIndex = ind
		}
	}
	return subjectExists, subjectIndex
}

func IsClusterUnavailable(err error) bool {
	if apiError, ok := err.(*httperror.APIError); ok {
		return apiError.Code == httperror.ClusterUnavailable
	}
	return false
}
