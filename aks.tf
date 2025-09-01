/*	The framework for building multiple AKS instances is here, however a couple things need thought out and coded before it is actually usable:
	1. There is a direct coupling of the AKS nodepools to a subnet name.  They will have to be programmatically linked
	2. Providers don't support for_each and aliases cannot be referenced via variables.  This means that anything using the kubernetes and helm providers (which the bulk of the AKS deployment does) needs to be staically configured via copy/paste.
		One possible solution is to keep this as a module, but again it will require further thought.
	3. The Nginx ingress DNS record isn't unique among separate instances
*/

locals {
	aks_clusternames = { for k, v in local.aks_instances :
		k => (v.name == "" ?
			lower("aks-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${v.numeric}")
			:
			lower("aks-${v.name}-${local.basic["local"].env_short}-${local.basic["local"].region_short}-${v.numeric}")
		)
	}

	aks_container_registries = { for k, v in flatten(
		[ for acr in data.terraform_remote_state.common.outputs.container_registries : 
			[ for instance_key, instance in local.aks_instances :
				{ 
					aks_key = instance_key 
					aks_value = instance
					acr = acr
				}
			]
		]) : "${v.aks_key}_${v.acr.name}" => v
	}
	kubernetes_version = { for k, v in local.aks_instances :
		k => (
			lookup(lookup(v.version, "env_override",{}), local.my_env_short, null) != null ? v.version.env_override[local.my_env_short] : v.version.default
		)
	}
}

#----- Create a kubernetes provider with the relevant credentials for the application cluster
# for_each is not supported here so it has to be done statically
provider "kubernetes" {
	host = azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].host
	username = azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].username
	password = azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].password
	client_certificate = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].client_certificate)
	client_key = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].client_key)
	cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].cluster_ca_certificate)
}

#----- Create a helm provider with the relevant credentials for the application cluster
# for_each is not supported here so it has to be done statically.
provider "helm" {

	kubernetes {
		host = azurerm_kubernetes_cluster.env["app"].kube_admin_config.0.host
		client_certificate = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].client_certificate)
		client_key = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].client_key)
		cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.env["app"].kube_admin_config[0].cluster_ca_certificate)
	}
}

#----- Register the encryption at host feature for Microsoft.Compute
resource "null_resource" "register_compute_encryption_at_host" {
	provisioner "local-exec" {
		command = <<EOT
			/usr/bin/az feature register --namespace Microsoft.Compute --name EncryptionAtHost || exit 1;
			/usr/bin/az provider register -n Microsoft.Compute || exit 1;
			
			elapsed_time=0;
			
			while [ "`az feature show --namespace Microsoft.Compute --name EncryptionAtHost | jq -r .properties.state`" != "Registered" ]; do
				sleep 5;
				
				elapsed_time=$((elapsed_time + 5));
				
				if [ $elapsed_time -ge 1200 ]; then
					echo "Timeout reached waiting for provider registration.";
					exit 1;
				fi
			done
		EOT
	}
}

#----- Create the Kubernetes cluster
resource "azurerm_kubernetes_cluster" "env" {
	for_each = local.aks_instances

	name = local.aks_clusternames[each.key]
	resource_group_name = azurerm_resource_group.env["compute"].name
	location = azurerm_resource_group.env["compute"].location
	
	kubernetes_version = local.kubernetes_version[each.key]
	
	dns_prefix = local.aks_clusternames[each.key]
	workload_identity_enabled = true
	oidc_issuer_enabled = true
	
	network_profile {
		network_plugin = "azure"
		outbound_type = "userDefinedRouting"
	}	
	
	sku_tier = "Premium"
	support_plan = each.value.support_plan
	automatic_channel_upgrade = null
	image_cleaner_enabled = true
	image_cleaner_interval_hours = 48
	
	api_server_access_profile {
		authorized_ip_ranges = distinct(concat(
			[ for v in local.resource_firewall_standard.ips : (substr(v, -3, 1) == "/" ? v : "${v}/32") ],
			[ for v in local.resource_firewall_fnf_wvd.ips : (substr(v, -3, 1) == "/" ? v : "${v}/32") ],
			[
				"${azurerm_public_ip.env[local.network_firewalls["backhaul"].pip].ip_address}/32",
				"${data.terraform_remote_state.common.outputs.build_servers[local.my_env_region_ref].ngw_pip}/32",
			],
		))
		
		vnet_integration_enabled = false
	}

	default_node_pool {
		name = "default"
		type = "VirtualMachineScaleSets"
		
		orchestrator_version = local.kubernetes_version[each.key]
		
		node_labels = each.value.nodepools["default"].labels

		# Only set the node count if auto scaling is turned off
		node_count = (each.value.nodepools["default"].enable_auto_scaling == false ?
			each.value.nodepools["default"].node_count : null
		)
		vm_size = lookup(lookup(each.value.nodepools["default"].node_size, "env_override", {}), local.basic["local"].env_short, null) != null ? each.value.nodepools["default"].node_size.env_override[local.basic["local"].env_short] : each.value.nodepools["default"].node_size.default
		os_disk_size_gb = each.value.nodepools["default"].disk_size
		
		max_pods = each.value.nodepools["default"].node_max_pods
		vnet_subnet_id 	= azurerm_subnet.env[each.value.nodepools["default"].subnet_key].id
		enable_node_public_ip = false
		
		# Only set the min and max node count if auto scaling is turned on
		enable_auto_scaling = each.value.nodepools["default"].enable_auto_scaling
		min_count = (each.value.nodepools["default"].enable_auto_scaling ? each.value.nodepools["default"].min_node_count : null)
		max_count = (each.value.nodepools["default"].enable_auto_scaling ? each.value.nodepools["default"].max_node_count : null)
		
		upgrade_settings {
			max_surge = "33%"
		}
		
		enable_host_encryption = true
		temporary_name_for_rotation = "tempdefault"
	}

	identity {
		type = "SystemAssigned"
	}
	
	role_based_access_control_enabled = true
	azure_active_directory_role_based_access_control {
		managed = true
		tenant_id = data.azurerm_subscription.current.tenant_id
		admin_group_object_ids = local.my_mg.rbac.aks_cluster_admin_group_oids
	}
	
	oms_agent {
		log_analytics_workspace_id = data.terraform_remote_state.common.outputs.log_analytics["default"].id
	}
	
	azure_policy_enabled = true
		
	tags = local.tags
	
	lifecycle {
		ignore_changes = [
			tags,
			custom_ca_trust_certificates_base64
		]
	}
	
	depends_on = [
		azurerm_firewall_application_rule_collection.allow_aks_provisioning,
		null_resource.register_compute_encryption_at_host,
		# This rule cannot be added because it causes a cyclical dependency since it relies on knowing the AKS API IP address
		# azurerm_firewall_network_rule_collection.allow_aks_api,
	]
}

#----- Network Contributor     !!!!! Networking will need to be refactored to align a subnet to a specific AKS cluster
resource "azurerm_role_assignment" "aks_mi_nodepool_subnets" {
	for_each = { for k, v in (flatten(
		[ for instance_key, instance_value in local.aks_instances :
			[ for vnet_key, vnet_value in local.network_vnets :
				[ for subnet_key, subnet_value in vnet_value.subnets :
					{
						instance_key = instance_key
						vnet_key = vnet_key
						subnet_key = subnet_key
						is_aks_nodepool = lookup(subnet_value, "is_aks_nodepool", false)
					}
				]
			]
		]
	)) : "${v.instance_key}_${v.vnet_key}_${v.subnet_key}" => v if v.is_aks_nodepool }
	

	scope = azurerm_subnet.env["${each.value.vnet_key}_${each.value.subnet_key}"].id
	role_definition_name = "Network Contributor"
	principal_id = azurerm_kubernetes_cluster.env[each.value.instance_key].identity[0].principal_id
}

#----- Virtual Machine Contributor
resource "azurerm_role_assignment" "aks_mi_vm_contrib" {
	for_each = local.aks_instances
	
	scope = data.azurerm_subscription.current.id
	role_definition_name = "Virtual Machine Contributor"
	principal_id = azurerm_kubernetes_cluster.env[each.key].kubelet_identity[0].object_id
}

#----- Managed Identity Operator
resource "azurerm_role_assignment" "aks_mi_managed_identity_operator" {
	for_each = local.aks_instances
	
	scope = data.azurerm_subscription.current.id
	role_definition_name = "Managed Identity Operator"
	principal_id = azurerm_kubernetes_cluster.env[each.key].kubelet_identity[0].object_id
}

#----- Container Registry Pull
resource "azurerm_role_assignment" "aks_mi_acr_role_assignment" {
	for_each = local.aks_container_registries

	scope = each.value.acr.id
	role_definition_name = "AcrPull"
	principal_id = azurerm_kubernetes_cluster.env[each.value.aks_key].kubelet_identity[0].object_id

}

#----- Monitoring Metrics Publisher
resource "azurerm_role_assignment" "aks_mi_metrics_role_assignment" {
	for_each = local.aks_instances

	scope = azurerm_kubernetes_cluster.env[each.key].id
	role_definition_name = "Monitoring Metrics Publisher"
	principal_id = azurerm_kubernetes_cluster.env[each.key].oms_agent[0].oms_agent_identity[0].object_id
}

#----- Add additional node pools
resource "azurerm_kubernetes_cluster_node_pool" "env" {
	for_each = { for k, v in (flatten(
		[ for instance_key, instance_value in local.aks_instances :
			[ for nodepool_key, nodepool_value in instance_value.nodepools :
				{
					instance_key = instance_key
					nodepool_key = nodepool_key
					version = instance_value.version
					node_count = nodepool_value.node_count
					node_size = lookup(lookup(nodepool_value.node_size, "env_override", {}), local.basic["local"].env_short, null) != null ? nodepool_value.node_size.env_override[local.basic["local"].env_short] : nodepool_value.node_size.default
					disk_size = nodepool_value.disk_size
					node_max_pods = nodepool_value.node_max_pods
					os_type = nodepool_value.os_type
					enable_auto_scaling = (local.envs_to_exceptions["${var.env_ref}_exos_cant_autoscale"] ? false : nodepool_value.enable_auto_scaling)
					min_node_count = nodepool_value.min_node_count
					max_node_count = nodepool_value.max_node_count
					labels = nodepool_value.labels
					taints = nodepool_value.taints
					subnet_key = nodepool_value.subnet_key
				}
			]
		]
	)) : "${v.instance_key}_${v.nodepool_key}" => v if v.nodepool_key != "default" } 
	
	name = each.value.nodepool_key
	kubernetes_cluster_id = azurerm_kubernetes_cluster.env[each.value.instance_key].id
	
	orchestrator_version = local.kubernetes_version[each.value.instance_key]
	
	os_type = each.value.os_type
	
	# Only set the node count if auto scaling is turned off or an exception is in place
	# Manual scale is also relevant in geo regions depending on dr_mode
	node_count = (
		each.value.enable_auto_scaling == false || local.services_active == false 
		? (
			local.services_active == false
			? 0 
			: (
				contains(
					keys(each.value.max_node_count.env_override),
					local.my_env_short
				)
				? each.value.max_node_count.env_override[local.my_env_short]
				: each.value.max_node_count.default
				)
			) 
		: null
	)
	vm_size = each.value.node_size
	os_disk_size_gb = each.value.disk_size
	
	max_pods = each.value.node_max_pods
	vnet_subnet_id 	= azurerm_subnet.env[each.value.subnet_key].id
	enable_node_public_ip = false
	
	enable_auto_scaling = (local.services_active ? each.value.enable_auto_scaling : false)
	min_count = (each.value.enable_auto_scaling && local.services_active 
	? (
		contains(
			keys(each.value.min_node_count.env_override),
			local.my_env_short
		)
		? each.value.min_node_count.env_override[local.my_env_short]
		: each.value.min_node_count.default
		) 
	: null
	)
	max_count = (each.value.enable_auto_scaling && local.services_active
	? (
		contains(
			keys(each.value.max_node_count.env_override),
			local.my_env_short
		)
		? each.value.max_node_count.env_override[local.my_env_short]
		: each.value.max_node_count.default
		)
	: null
	)

	node_taints = each.value.taints
	node_labels = each.value.labels
	
	upgrade_settings {
		max_surge = "33%"
	}
	
	enable_host_encryption = true
	
	tags = local.tags
	lifecycle {
		ignore_changes = [
			tags,
		]
	}
	depends_on = [ azurerm_kubernetes_cluster.env ]
}

#----- Do AKS image updates on nodepools on the same cycle as linux patches
resource "null_resource" "aks_image_updates" {
	for_each = { for k, v in (flatten(
		[ for instance_key, instance_value in local.aks_instances :
			[ for nodepool_key, nodepool_value in instance_value.nodepools :
				{
					instance_key = instance_key
					nodepool_key = nodepool_key
				}
			]
		]
	)) : "${v.instance_key}_${v.nodepool_key}" => v } 

	triggers = {
		keeper = var.vm_patching_keeper
	}
	
	provisioner "local-exec" {
		command = "/usr/bin/az aks nodepool upgrade --resource-group $RG_NAME --cluster-name $CLUSTER_NAME --name $NODEPOOL_NAME --node-image-only"
		
		environment = {
			RG_NAME = azurerm_kubernetes_cluster.env[each.value.instance_key].resource_group_name
			CLUSTER_NAME = azurerm_kubernetes_cluster.env[each.value.instance_key].name
			NODEPOOL_NAME = each.value.nodepool_key
		}
	}
	
	depends_on = [
		azurerm_kubernetes_cluster.env,
		azurerm_kubernetes_cluster_node_pool.env,
	]

}

#----- Create the deployment service account
# Create the namespace
resource "kubernetes_namespace" "deploy_bot" {
	for_each = local.aks_instances
	
	metadata {
		name = "deploy-bot"
	}
	
	lifecycle {
		ignore_changes = [
			metadata[0].annotations, metadata[0].labels
		]
	}
}

#----- Create the deploy-bot service account
resource "kubernetes_service_account" "deploy_bot" {
	for_each = local.aks_instances

	automount_service_account_token = false
	
	metadata {
		name = "deploy-bot"
		namespace = kubernetes_namespace.deploy_bot[each.key].metadata[0].name
	}
}

resource "kubernetes_secret" "deploy_bot" {
	for_each = local.aks_instances

	metadata {
		annotations = {
			"kubernetes.io/service-account.name" = kubernetes_service_account.deploy_bot[each.key].metadata[0].name
		}
		
		name = "deploy-bot"
		namespace = kubernetes_namespace.deploy_bot[each.key].metadata[0].name
	}
	
	type = "kubernetes.io/service-account-token"
}
	
# Grant the service account admin on the cluster 
resource "kubernetes_cluster_role_binding" "deploy_bot_to_admin" {
	for_each = local.aks_instances

	metadata {
		name = "deploy-bot-binding"
	}
	
	role_ref {
		api_group = "rbac.authorization.k8s.io"
		kind = "ClusterRole"
		name = "cluster-admin"
	}
	
	subject {
		api_group = ""
		kind = "User"
		name = "system:serviceaccount:${kubernetes_service_account.deploy_bot[each.key].metadata[0].namespace}:${kubernetes_service_account.deploy_bot[each.key].metadata[0].name}"
	}
}

#----- Create the cluster role binding for admins
resource "kubernetes_cluster_role_binding" "admin_groups" {
	for_each = local.aks_instances
	
	metadata {
		name = "cluster-admins-binding"
	}
	
	role_ref {
		api_group = "rbac.authorization.k8s.io"
		kind = "ClusterRole"
		name = "cluster-admin"
	}
	
	dynamic "subject" {
		for_each = local.my_mg.rbac.aks_cluster_admin_group_oids
		
		content {
			api_group = "rbac.authorization.k8s.io"
			kind = "Group"
			name = subject.value
		}
	}
}

#----- Create the cluster role and binding for writers
resource "kubernetes_cluster_role" "writers" {
	for_each = local.aks_instances
	
	metadata {
		name = "cluster-writers"
	}
	
	rule {
		api_groups = [ "" ]
		resources = [
			"deployments",
			"deployments.app",
			"configmaps",
			"events",
			"namespaces",
			"pods",
			"pods/log",
			"services",
			"cronjobs.batch",
			"daemonsets.apps",
			"deployments",
			"endpoints",
			"events.events.k8s.io",
			"horizontalpodautoscalers.autoscaling",
			"jobs.batch",
			"nodes.metrics.k8s.io",
			"pods.metrics.k8s.io",
			"podtemplates",
			"replicasets.apps",
			"replicationcontrollers",
			"resourcequotas",
			"statefulsets.apps",
		]
		verbs = [ "delete", "patch", "update" ]
	}
   
	rule {
		api_groups = [ "" ]
		resources = [
			"configmaps",
			"deployments",
			"deployments.app",
			"events",
			"limitranges",
			"namespaces",
			"pods",
			"pods/log",
			"pods/exec",
			"replicasets",
			"resourcequotas",
			"secrets",
			"serviceaccounts",
			"services",
		]
		verbs = [ "get", "list", "watch" ]
	}
   
	rule {
		api_groups = [ "apps", "autoscaling" ]
		resources = [
			"deployments",
			"deployments.app",
			"deployments/scale",
		]
		verbs = [ "get", "list", "watch", "patch" ]
	}
	
	rule {
		api_groups = [ "batch" ]
		resources = [ "jobs" ]
		verbs = [ "get", "list", "watch" ]
	}
	
	rule {
		api_groups = [ "extensions" ]
		resources = [ "deployments" ]
		verbs = [ "get" ]
	}
	
	rule {
		api_groups = [ "" ]
		resources = [ "pods/exec" ]
		verbs = [ "create" ]
	}

	rule {
		api_groups = [ "metrics.k8s.io" ]
		resources = [ "pods", "nodes" ]
		verbs = [ "get", "list", "watch" ]
	}
}

resource "kubernetes_cluster_role_binding" "writer_groups" {
	for_each = local.aks_instances

	metadata {
		name = "k8s-cluster-writer-binding"
	}
	
	role_ref {
		api_group = "rbac.authorization.k8s.io"
		kind = "ClusterRole"
		name = "cluster-writers"
	}
	
	dynamic "subject" {
		for_each = local.my_mg.rbac.aks_cluster_writer_group_oids
		
		content {
			api_group = "rbac.authorization.k8s.io"
			kind = "Group"
			name = subject.value
		}
	}
}

#----- Create the cluster role and binding for readers
resource "kubernetes_cluster_role" "readers" {
	for_each = local.aks_instances

	metadata {
		name = "k8s-cluster-reader"
	}
	
	rule {
		api_groups = [ "" ]
		resources = [
			"deployments",
			"deployments.app",
			"configmaps",
			"events",
			"namespaces",
			"pods",
			"pods/log",
			"services",
			"cronjobs.batch",
			"daemonsets.apps",
			"endpoints",
			"events.events.k8s.io",
			"horizontalpodautoscalers.autoscaling",
			"jobs.batch",
			"limitranges",
			"nodes.metrics.k8s.io",
			"pods.metrics.k8s.io",
			"podtemplates",
			"replicasets.apps",
			"replicasets",
			"replicationcontrollers",
			"resourcequotas",
			"serviceaccounts",
			"statefulsets.apps",
		]
		verbs = [ "get", "list", "watch" ]
	}

	rule {
		api_groups = [ "" ]
		resources = [ "secrets" ]
		verbs = [ "list" ]
	}
   
	rule {
		api_groups = [ "apps", "autoscaling" ]
		resources = [ "deployments", "deployments.app" ]
		verbs = [ "get", "list", "watch" ]
	}
	
	rule {
		api_groups = [ "batch" ]
		resources = [ "jobs" ]
		verbs = [ "get", "list", "watch" ]
	}

	rule {
		api_groups = [ "metrics.k8s.io" ]
		resources = [ "pods", "nodes" ]
		verbs = [ "get", "list", "watch" ]
	}
}

resource "kubernetes_cluster_role_binding" "reader_groups" {
	for_each = local.aks_instances

	metadata {
		name = "k8s-cluster-reader-binding"
	}
	
	role_ref {
		api_group = "rbac.authorization.k8s.io"
		kind = "ClusterRole"
		name = "k8s-cluster-reader"
	}
	
	dynamic "subject" {
		for_each = local.my_mg.rbac.aks_cluster_reader_group_oids
		
		content {
			api_group = "rbac.authorization.k8s.io"
			kind = "Group"
			name = subject.value
		}
	}
}
