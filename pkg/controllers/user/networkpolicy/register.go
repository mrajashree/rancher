package networkpolicy

import (
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
)

// Register initializes the controllers and registers
func Register(cluster *config.UserContext) {
	logrus.Infof("Registering project network policy")

	pnpLister := cluster.Management.Management.ProjectNetworkPolicies("").Controller().Lister()
	pnpClient := cluster.Management.Management.ProjectNetworkPolicies("").ObjectClient()
	projClient := cluster.Management.Management.Projects("").ObjectClient()
	nodeLister := cluster.Core.Nodes("").Controller().Lister()
	nsLister := cluster.Core.Namespaces("").Controller().Lister()
	k8sClient := cluster.K8sClient
	pods := cluster.Core.Pods("")
	machines := cluster.Management.Management.Nodes(cluster.ClusterName)

	npmgr := &netpolMgr{nsLister, nodeLister, pods, k8sClient}
	ps := &projectSyncer{pnpLister, pnpClient, projClient}
	nss := &nsSyncer{npmgr}
	pnps := &projectNetworkPolicySyncer{npmgr}
	podHandler := &podHandler{npmgr, pods}
	serviceHandler := &serviceHandler{npmgr}
	nodeHandler := &nodeHandler{npmgr, machines, cluster.ClusterName}

	cluster.Management.Management.Projects("").Controller().AddClusterScopedHandler("projectSyncer", cluster.ClusterName, ps.Sync)
	cluster.Management.Management.ProjectNetworkPolicies("").AddClusterScopedHandler("projectNetworkPolicySyncer", cluster.ClusterName, pnps.Sync)
	cluster.Core.Namespaces("").AddHandler("namespaceLifecycle", nss.Sync)

	cluster.Core.Pods("").AddHandler("podHandler", podHandler.Sync)
	cluster.Core.Services("").AddHandler("serviceHandler", serviceHandler.Sync)
	cluster.Management.Management.Nodes(cluster.ClusterName).Controller().AddHandler("nodeHandler", nodeHandler.Sync)
}
