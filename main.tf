terraform {
  required_providers {
    azapi = {
      source  = "Azure/azapi"
      #version = "2.6.0"
      version = "~>2.6"
    }
  }
}

provider "azurerm" {
  features {
  }
subscription_id = var.F-SubscriptionID
}
provider "azapi" {}

#variables
variable "A-location" {
    description = "Location of the resources"
    
}

variable "B-resource_group_name" {
    description = "Name of the resource group to create"
    
}

variable "C-home_public_ip" {
    description = "Your home public ip address"
    
}

variable "D-username" {
    description = "Username for Virtual Machines"
    
}

variable "E-password" {
    description = "Password for Virtual Machines"
    sensitive = true
    
}

variable "F-SubscriptionID" {
  description = "Subscription ID to use"
  
}


resource "azurerm_resource_group" "RG" {
  location = var.A-location
  name     = var.B-resource_group_name
}

#logic app to self destruct resourcegroup after 24hrs
data "azurerm_subscription" "sub" {
}

resource "azurerm_logic_app_workflow" "workflow1" {
  location = azurerm_resource_group.RG.location
  name     = "labdelete"
  resource_group_name = azurerm_resource_group.RG.name
  identity {
    type = "SystemAssigned"
  }
  depends_on = [
    azurerm_resource_group.RG,
  ]
}
resource "azurerm_role_assignment" "contrib1" {
  scope = azurerm_resource_group.RG.id
  role_definition_name = "Contributor"
  principal_id  = azurerm_logic_app_workflow.workflow1.identity[0].principal_id
  depends_on = [azurerm_logic_app_workflow.workflow1]
}

resource "azurerm_resource_group_template_deployment" "apiconnections" {
  name                = "group-deploy"
  resource_group_name = azurerm_resource_group.RG.name
  deployment_mode     = "Incremental"
  template_content = <<TEMPLATE
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Web/connections",
            "apiVersion": "2016-06-01",
            "name": "arm-1",
            "location": "${azurerm_resource_group.RG.location}",
            "kind": "V1",
            "properties": {
                "displayName": "labdeleteconn1",
                "authenticatedUser": {},
                "statuses": [
                    {
                        "status": "Ready"
                    }
                ],
                "connectionState": "Enabled",
                "customParameterValues": {},
                "alternativeParameterValues": {},
                "parameterValueType": "Alternative",
                "createdTime": "2023-05-21T23:07:20.1346918Z",
                "changedTime": "2023-05-21T23:07:20.1346918Z",
                "api": {
                    "name": "arm",
                    "displayName": "Azure Resource Manager",
                    "description": "Azure Resource Manager exposes the APIs to manage all of your Azure resources.",
                    "iconUri": "https://connectoricons-prod.azureedge.net/laborbol/fixes/path-traversal/1.0.1552.2695/arm/icon.png",
                    "brandColor": "#003056",
                    "id": "/subscriptions/${data.azurerm_subscription.sub.subscription_id}/providers/Microsoft.Web/locations/${azurerm_resource_group.RG.location}/managedApis/arm",
                    "type": "Microsoft.Web/locations/managedApis"
                },
                "testLinks": []
            }
        },
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "labdelete",
            "location": "${azurerm_resource_group.RG.location}",
            "dependsOn": [
                "[resourceId('Microsoft.Web/connections', 'arm-1')]"
            ],
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Recurrence": {
                            "recurrence": {
                                "frequency": "Minute",
                                "interval": 3,
                                "startTime": "${timeadd(timestamp(),"24h")}"
                            },
                            "evaluatedRecurrence": {
                                "frequency": "Minute",
                                "interval": 3,
                                "startTime": "${timeadd(timestamp(),"24h")}"
                            },
                            "type": "Recurrence"
                        }
                    },
                    "actions": {
                        "Delete_a_resource_group": {
                            "runAfter": {},
                            "type": "ApiConnection",
                            "inputs": {
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['arm']['connectionId']"
                                    }
                                },
                                "method": "delete",
                                "path": "/subscriptions/@{encodeURIComponent('${data.azurerm_subscription.sub.subscription_id}')}/resourcegroups/@{encodeURIComponent('${azurerm_resource_group.RG.name}')}",
                                "queries": {
                                    "x-ms-api-version": "2016-06-01"
                                }
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "arm": {
                                "connectionId": "[resourceId('Microsoft.Web/connections', 'arm-1')]",
                                "connectionName": "arm-1",
                                "connectionProperties": {
                                    "authentication": {
                                        "type": "ManagedServiceIdentity"
                                    }
                                },
                                "id": "/subscriptions/${data.azurerm_subscription.sub.subscription_id}/providers/Microsoft.Web/locations/${azurerm_resource_group.RG.location}/managedApis/arm"
                            }
                        }
                    }
                }
            }
        }
    ]
}
TEMPLATE
}

resource "random_pet" "name" {
  length = 1
}

#log analytics workspace
resource "azurerm_log_analytics_workspace" "LAW" {
  name                = "LAW-${random_pet.name.id}"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  
}

#vnets and subnets
resource "azurerm_virtual_network" "hub-vnet" {
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.RG.location
  name                = "AZ-hub-vnet"
  resource_group_name = azurerm_resource_group.RG.name
  subnet {
    address_prefixes     = ["10.0.0.0/24"]
    name                 = "default"
    
  }
  subnet {
    address_prefixes     = ["10.0.1.0/24"]
    name                 = "AzureFirewallSubnet" 
  }
  
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
}
resource "azurerm_virtual_network" "spoke1-vnet" {
  address_space       = ["10.150.0.0/16"]
  location            = azurerm_resource_group.RG.location
  name                = "AZ-spoke1-vnet"
  resource_group_name = azurerm_resource_group.RG.name
  subnet {
    address_prefixes     = ["10.150.0.0/24"]
    name                 = "default"
    
  }  
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_virtual_network" "spoke2-vnet" {
  address_space       = ["10.250.0.0/16"]
  location            = azurerm_resource_group.RG.location
  name                = "AZ-spoke2-vnet"
  resource_group_name = azurerm_resource_group.RG.name
  subnet {
    address_prefixes     = ["10.250.0.0/24"]
    name                 = "default"
    
  }
  
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

#Public IPs
resource "azurerm_public_ip" "hubvm-pip" {
  name                = "hubvm-pip"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  allocation_method = "Static"
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

resource "azurerm_public_ip" "spoke1vm-pip" {
  name                = "spoke1vm-pip"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  allocation_method = "Static"
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_public_ip" "spoke2vm-pip" {
  name                = "spoke2vm-pip"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  allocation_method = "Static"
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

resource "azurerm_public_ip" "azfw-pip" {
  name                = "azfw-pip"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  allocation_method = "Static"
  sku = "Standard"
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

#vNIC's
resource "azurerm_network_interface" "hubvm-nic" {
  location            = azurerm_resource_group.RG.location
  name                = "hubvm-nic"
  resource_group_name = azurerm_resource_group.RG.name
  ip_configuration {
    name                          = "ipconfig1"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.hubvm-pip.id
    subnet_id                     = azurerm_virtual_network.hub-vnet.subnet.*.id[0]
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_network_interface" "spoke1vm-nic" {
  location            = azurerm_resource_group.RG.location
  name                = "spoke1vm-nic"
  resource_group_name = azurerm_resource_group.RG.name
  ip_configuration {
    name                          = "ipconfig1"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.spoke1vm-pip.id
    subnet_id                     = azurerm_virtual_network.spoke1-vnet.subnet.*.id[0]
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_network_interface" "spoke2vm-nic" {
  location            = azurerm_resource_group.RG.location
  name                = "spoke2vm-nic"
  resource_group_name = azurerm_resource_group.RG.name
  ip_configuration {
    name                          = "ipconfig1"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.spoke2vm-pip.id
    subnet_id                     = azurerm_virtual_network.spoke2-vnet.subnet.*.id[0]
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

#Azfirewall and policy
resource "azurerm_firewall_policy" "azfwpolicy" {
  name                = "azfw-policy"
  resource_group_name = azurerm_resource_group.RG.name
  location            = azurerm_resource_group.RG.location
  sku = "Standard"
  
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
}
resource "azurerm_firewall_policy_rule_collection_group" "azfwpolicyrcg" {
  name               = "azfwpolicy-rcg"
  firewall_policy_id = azurerm_firewall_policy.azfwpolicy.id
  priority           = 500
  network_rule_collection {
    name     = "network_rule_collection1"
    priority = 400
    action   = "Allow"
    rule {
      name                  = "network_rule_collection1_rule1"
      protocols             = ["Any"]
      source_addresses      = ["*"]
      destination_addresses = ["*"]
      destination_ports     = ["*"]
    }
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
    }
  
}
resource "azurerm_firewall" "azfw" {
  name                = "AzureFirewall"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id = azurerm_firewall_policy.azfwpolicy.id

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_virtual_network.hub-vnet.subnet.*.id[1]
    public_ip_address_id = azurerm_public_ip.azfw-pip.id
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
#firewall logging
resource "azurerm_monitor_diagnostic_setting" "fwlogs"{
  name = "fwlogs-${random_pet.name.id}"
  target_resource_id = azurerm_firewall.azfw.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.LAW.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "AZFWNetworkRule"
  }
  enabled_log {
    category = "AZFWApplicationRule"
  }
  enabled_log {
    category = "AZFWNatRule"
  }
  enabled_log {
    category = "AZFWThreatIntel"
  }
  enabled_log {
    category = "AZFWIdpsSignature"
  }
  enabled_log {
    category = "AZFWDnsQuery"
  }
  enabled_log {
    category = "AZFWFqdnResolveFailure"
  }
  enabled_log {
    category = "AZFWFatFlow"
  }
  enabled_log {
    category = "AZFWFlowTrace"
  }
}
data "azurerm_firewall" "azfw" {
  name                = azurerm_firewall.azfw.name
  resource_group_name = azurerm_resource_group.RG.name
  
}

#VM's
resource "azurerm_windows_virtual_machine" "hubvm" {
  admin_password        = var.E-password
  admin_username        = var.D-username
  location              = azurerm_resource_group.RG.location
  name                  = "hubvm"
  network_interface_ids = [azurerm_network_interface.hubvm-nic.id]
  resource_group_name   = azurerm_resource_group.RG.name
  size                  = "Standard_B2ms"
  identity {
    type = "SystemAssigned"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
  source_image_reference {
    offer     = "WindowsServer"
    publisher = "MicrosoftWindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_virtual_machine_extension" "killhubvmfirewall" {
  auto_upgrade_minor_version = true
  name                       = "killhubvmfirewall"
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  virtual_machine_id         = azurerm_windows_virtual_machine.hubvm.id
  settings = <<SETTINGS
    {
      "commandToExecute": "powershell -command \"Set-NetFirewallProfile -Enabled False\""
    }
  SETTINGS
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_windows_virtual_machine" "spoke1vm" {
  admin_password        = var.E-password
  admin_username        = var.D-username
  location              = azurerm_resource_group.RG.location
  name                  = "spoke1vm"
  network_interface_ids = [azurerm_network_interface.spoke1vm-nic.id]
  resource_group_name   = azurerm_resource_group.RG.name
  size                  = "Standard_B2ms"
  identity {
    type = "SystemAssigned"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
  source_image_reference {
    offer     = "WindowsServer"
    publisher = "MicrosoftWindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_virtual_machine_extension" "killspoke1vmfirewall" {
  auto_upgrade_minor_version = true
  name                       = "killspoke1vmfirewall"
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  virtual_machine_id         = azurerm_windows_virtual_machine.spoke1vm.id
  settings = <<SETTINGS
    {
      "commandToExecute": "powershell -command \"Set-NetFirewallProfile -Enabled False\""
    }
  SETTINGS
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_windows_virtual_machine" "spoke2vm" {
  admin_password        = var.E-password
  admin_username        = var.D-username
  location              = azurerm_resource_group.RG.location
  name                  = "spoke2vm"
  network_interface_ids = [azurerm_network_interface.spoke2vm-nic.id]
  resource_group_name   = azurerm_resource_group.RG.name
  size                  = "Standard_B2ms"
  identity {
    type = "SystemAssigned"
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
  source_image_reference {
    offer     = "WindowsServer"
    publisher = "MicrosoftWindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}
resource "azurerm_virtual_machine_extension" "killspoke2vmfirewall" {
  auto_upgrade_minor_version = true
  name                       = "killspoke2vmfirewall"
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  virtual_machine_id         = azurerm_windows_virtual_machine.spoke2vm.id
  settings = <<SETTINGS
    {
      "commandToExecute": "powershell -command \"Set-NetFirewallProfile -Enabled False\""
    }
  SETTINGS
  timeouts {
    create = "2h"
    read = "2h"
    update = "2h"
    delete = "2h"
  }
  
}

#Network Manager

resource "azurerm_network_manager" "network_manager_instance" {
  name                = "network-manager1"
  location            = azurerm_resource_group.RG.location
  resource_group_name = azurerm_resource_group.RG.name
  scope_accesses      = ["Connectivity", "SecurityAdmin","Routing"]
  description         = "network manager"
  scope {
    subscription_ids = [data.azurerm_subscription.sub.id]
  }
}

resource "azurerm_network_manager_network_group" "network_group" {
  name               = "network-group1"
  network_manager_id = azurerm_network_manager.network_manager_instance.id
}

resource "azurerm_network_manager_static_member" "member1" {
  name                      = "net-member1"
  network_group_id          = azurerm_network_manager_network_group.network_group.id
  target_virtual_network_id = azurerm_virtual_network.hub-vnet.id
}
resource "azurerm_network_manager_static_member" "member2" {
  name                      = "net-member2"
  network_group_id          = azurerm_network_manager_network_group.network_group.id
  target_virtual_network_id = azurerm_virtual_network.spoke1-vnet.id
}
resource "azurerm_network_manager_static_member" "member3" {
  name                      = "net-member3"
  network_group_id          = azurerm_network_manager_network_group.network_group.id
  target_virtual_network_id = azurerm_virtual_network.spoke2-vnet.id
}

resource "azurerm_network_manager_connectivity_configuration" "connconf" {
  name                  = "connectivity-conf1"
  network_manager_id    = azurerm_network_manager.network_manager_instance.id
  connectivity_topology = "HubAndSpoke"
  applies_to_group {
    
    group_connectivity = "None"
    network_group_id   = azurerm_network_manager_network_group.network_group.id
  }
  hub {
    resource_id   = azurerm_virtual_network.hub-vnet.id
    resource_type = "Microsoft.Network/virtualNetworks"
  }
}

resource "azurerm_network_manager_security_admin_configuration" "secconf" {
  name               = "admin-conf1"
  network_manager_id = azurerm_network_manager.network_manager_instance.id
}

resource "azurerm_network_manager_admin_rule_collection" "rulecol1" {
  name                            = "admin-rule-collection1"
  security_admin_configuration_id = azurerm_network_manager_security_admin_configuration.secconf.id
  network_group_ids               = [azurerm_network_manager_network_group.network_group.id]
}

resource "azurerm_network_manager_admin_rule" "rule1" {
  name                     = "admin-rule1"
  admin_rule_collection_id = azurerm_network_manager_admin_rule_collection.rulecol1.id
  action                   = "Allow"
  direction                = "Inbound"
  priority                 = 1
  protocol                 = "Tcp"
  source_port_ranges       = ["0-65535"]
  destination_port_ranges  = ["3389"]
  source {
    address_prefix_type = "IPPrefix"
    address_prefix      = var.C-home_public_ip
  }
  destination {
    address_prefix_type = "IPPrefix"
    address_prefix      = "*"
  }
  
  description = "admin rule"
}

resource "azurerm_network_manager_routing_configuration" "routeconf" {
  name               = "routing-configuration1"
  network_manager_id = azurerm_network_manager.network_manager_instance.id
}

resource "azurerm_network_manager_routing_rule_collection" "routerulecol1" {
  name                     = "routing-rule-collection1"
  routing_configuration_id = azurerm_network_manager_routing_configuration.routeconf.id
  network_group_ids        = [azurerm_network_manager_network_group.network_group.id]
  description              = "routing rule collection"
}

resource "azurerm_network_manager_routing_rule" "routerule1" {
  name               = "routing-rule1"
  rule_collection_id = azurerm_network_manager_routing_rule_collection.routerulecol1.id
  description        = "to internet"

  destination {
    type    = "AddressPrefix"
    address = "${var.C-home_public_ip}/32"
  }

  next_hop {
    type = "Internet"
  }
}
resource "azurerm_network_manager_routing_rule" "routerule2" {
  name               = "routing-rule2"
  rule_collection_id = azurerm_network_manager_routing_rule_collection.routerulecol1.id
  description        = "to azfw"

  destination {
    type    = "AddressPrefix"
    address = "0.0.0.0/0"
  }

  next_hop {
    type = "VirtualAppliance"    
    address = "10.0.1.4"  
  }
  depends_on = [ azurerm_network_manager_routing_rule.routerule1,azurerm_firewall.azfw ]
}

resource "azurerm_network_manager_deployment" "commit_deployment_connectivity" {
  network_manager_id = azurerm_network_manager.network_manager_instance.id
  location           = azurerm_resource_group.RG.location
  scope_access       = "Connectivity"  
  configuration_ids  = [azurerm_network_manager_connectivity_configuration.connconf.id]
}
resource "azurerm_network_manager_deployment" "commit_deployment_securityadmin" {
  network_manager_id = azurerm_network_manager.network_manager_instance.id
  location           = azurerm_resource_group.RG.location
  scope_access       = "SecurityAdmin"
  configuration_ids  = [azurerm_network_manager_security_admin_configuration.secconf.id]
  depends_on = [ azurerm_network_manager_admin_rule.rule1 ]
}
resource "azurerm_network_manager_deployment" "commit_deployment_routing" {
  network_manager_id = azurerm_network_manager.network_manager_instance.id
  location           = azurerm_resource_group.RG.location
  scope_access       = "Routing"
  configuration_ids  = [azurerm_network_manager_routing_configuration.routeconf.id]
  depends_on = [ azurerm_network_manager_routing_rule.routerule2 ]
}

resource "azurerm_network_manager_verifier_workspace" "verifier" {
  name               = "network-verifier1"
  network_manager_id = azurerm_network_manager.network_manager_instance.id
  location           = azurerm_resource_group.RG.location
}

resource "azapi_resource" "intent1" {
  body = {
    properties = {
      description           = ""
      destinationResourceId = azurerm_windows_virtual_machine.spoke1vm.id
      ipTraffic = {
        destinationIps   = ["${azurerm_public_ip.spoke1vm-pip.ip_address}"]
        destinationPorts = ["3389"]
        protocols        = ["TCP"]
        sourceIps        = ["${var.C-home_public_ip}"]
        sourcePorts      = ["*"]
      }
      provisioningState = "Succeeded"
      sourceResourceId  = "internet"
    }
  }
  ignore_casing             = false
  ignore_missing_property   = true
  ignore_null_property      = false
  name                      = "intent1"
  parent_id                 = azurerm_network_manager_verifier_workspace.verifier.id
  schema_validation_enabled = true
  type                      = "Microsoft.Network/networkManagers/verifierWorkspaces/reachabilityAnalysisIntents@2024-07-01"
}
