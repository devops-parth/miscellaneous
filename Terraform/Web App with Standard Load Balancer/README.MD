$$
\bigstar \textcolor{purple}{Web ~App ~with ~Azure ~SLB }
$$

# Terraform Block (Version)
### Mention the Required Version of Terraform and all the Resource 

```hcl
# Terraform Block
terraform {
  required_version = ">= 1.0.0"
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = ">= 2.0" 
    }
    random = {
      source = "hashicorp/random"
      version = ">= 3.0"
    }
    null = {
      source = "hashicorp/null"
      version = ">= 3.0"
    }    
  }
}

# Provider Block
provider "azurerm" {
 features {}          
}
```
#
# Random Resource
### Random String Resource for Unique Naming
```hcl
resource "random_string" "myrandom" {
  length = 6
  upper = false 
  special = false
  number = false   
}
```
#
# Declaring Variables
### Generic Input Variables
```hcl
# Business Division
variable "business_divsion" {
  description = "Business Division in the large organization this Infrastructure belongs"
  type = string
  default = "sap"
}
# Environment Variable
variable "environment" {
  description = "Environment Variable used as a prefix"
  type = string
  default = "dev"
}
```
### Resource Group Input Variables
```hcl
# Azure Resource Group Name 
variable "resource_group_name" {
  description = "Resource Group Name"
  type = string
  default = "rg-default"  
}

# Azure Resources Location
variable "resource_group_location" {
  description = "Region in which Azure Resources to be created"
  type = string
  default = "eastus2"  
}
```
#
# Locals
## Define Local Values in Terraform. It is only for ease of good naming practices
```hcl
locals {
  owners = var.business_divsion
  environment = var.environment
  resource_name_prefix = "${var.business_divsion}-${var.environment}"
  #name = "${local.owners}-${local.environment}"
  common_tags = {
    owners = local.owners
    environment = local.environment
  }
} 
```
#
# Azure Resource Group
```hcl
resource "azurerm_resource_group" "rg" {
  # name = "${local.resource_name_prefix}-${var.resource_group_name}"
  name = "${local.resource_name_prefix}-${var.resource_group_name}-${random_string.myrandom.id}"
  location = var.resource_group_location
  tags = local.common_tags
}
```
#
# Virtual Network
### Virtual Network variable
```hcl
## Virtual Network
variable "vnet_name" {
  description = "Virtual Network name"
  type = string
  default = "vnet-default"
}
variable "vnet_address_space" {
  description = "Virtual Network address_space"
  type = list(string)
  default = ["10.0.0.0/16"]
}
```

### Subnets and Subnet NSG's variable
```hcl
# Web Subnet Name
variable "web_subnet_name" {
  description = "Virtual Network Web Subnet Name"
  type = string
  default = "websubnet"
}
# Web Subnet Address Space
variable "web_subnet_address" {
  description = "Virtual Network Web Subnet Address Spaces"
  type = list(string)
  default = ["10.0.1.0/24"]
}

# App Subnet Name
variable "app_subnet_name" {
  description = "Virtual Network App Subnet Name"
  type = string
  default = "appsubnet"
}
# App Subnet Address Space
variable "app_subnet_address" {
  description = "Virtual Network App Subnet Address Spaces"
  type = list(string)
  default = ["10.0.11.0/24"]
}

# Database Subnet Name
variable "db_subnet_name" {
  description = "Virtual Network Database Subnet Name"
  type = string
  default = "dbsubnet"
}
# Database Subnet Address Space
variable "db_subnet_address" {
  description = "Virtual Network Database Subnet Address Spaces"
  type = list(string)
  default = ["10.0.21.0/24"]
}

# Bastion / Management Subnet Name
variable "bastion_subnet_name" {
  description = "Virtual Network Bastion Subnet Name"
  type = string
  default = "bastionsubnet"
}
# Bastion / Management Subnet Address Space
variable "bastion_subnet_address" {
  description = "Virtual Network Bastion Subnet Address Spaces"
  type = list(string)
  default = ["10.0.100.0/24"]
}
```
#
# Create Virtual Network
```hcl
resource "azurerm_virtual_network" "vnet" {
  name                = "${local.resource_name_prefix}-${var.vnet_name}"
  #Virtual Network variable & Local Variable
  address_space       = var.vnet_address_space #Subnet of Vnet
  #Virtual Network variable
  location            = azurerm_resource_group.rg.location
  # Resource-1: Azure Resource Group
  resource_group_name = azurerm_resource_group.rg.name
  # Resource-1: Azure Resource Group
  tags = local.common_tags
  ## Locals Values in Terraform
}
```
#
# Resource-1: Create WebTier Subnet
```hcl
resource "azurerm_subnet" "websubnet" {
  name                 = "${azurerm_virtual_network.vnet.name}-${var.web_subnet_name}"
  # Create Virtual Network & Subnets and Subnet NSG's variable
  resource_group_name  = azurerm_resource_group.rg.name
  # Resource-1: Azure Resource Group
  virtual_network_name = azurerm_virtual_network.vnet.name
  # Create Virtual Network
  address_prefixes     = var.web_subnet_address  
  #Subnets and Subnet NSG's variable
}
```

# Resource-2: Create Network Security Group (NSG)
```hcl
resource "azurerm_network_security_group" "web_subnet_nsg" {
  name                = "${azurerm_subnet.websubnet.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
```

# Resource-3: Create NSG Rules
```hcl
## Locals Block for Security Rules
locals {
  web_inbound_ports_map = {
    "100" : "80",
    "110" : "443",
    "120" : "22"
     # If the key starts with a number, you must use the colon syntax ":" instead of "="
  } 
}
## NSG Inbound Rule for WebTier Subnets
resource "azurerm_network_security_rule" "web_nsg_rule_inbound" {
  for_each = local.web_inbound_ports_map
  name                        = "Rule-Port-${each.value}"
  priority                    = each.key
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = each.value 
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.web_subnet_nsg.name
}
```

# Resource-4: Associate NSG and Subnet
```hcl
resource "azurerm_subnet_network_security_group_association" "web_subnet_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.web_nsg_rule_inbound]
  # Every NSG Rule Association will disassociate NSG from Subnet and Associate it, so we associate it only after NSG is completely created - Azure Provider Bug https://github.com/terraform-providers/terraform-provider-azurerm/issues/354  
  subnet_id                 = azurerm_subnet.websubnet.id
  network_security_group_id = azurerm_network_security_group.web_subnet_nsg.id
}
```
#
# Resource-1: Create AppTier Subnet
```hcl
resource "azurerm_subnet" "appsubnet" {
  name                 = "${azurerm_virtual_network.vnet.name}-${var.app_subnet_name}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.app_subnet_address
  # Subnets and Subnet NSG's variable (App Subnet Range) 
}
```
# Resource-2: Create Network Security Group (NSG)
```hcl
resource "azurerm_network_security_group" "app_subnet_nsg" {
  name                = "${azurerm_subnet.appsubnet.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
```
# Resource-3: Create NSG Rules
```hcl
## Locals Block for Security Rules
locals {
  app_inbound_ports_map = {
    "100" : "80",
    "110" : "443",
    "120" : "8080",
    "130" : "22"
  } 
}
## NSG Inbound Rule for AppTier Subnets
resource "azurerm_network_security_rule" "app_nsg_rule_inbound" {
  for_each = local.app_inbound_ports_map
  name                        = "Rule-Port-${each.value}"
  priority                    = each.key
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = each.value 
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.app_subnet_nsg.name
}
```
# Resource-4: Associate NSG and Subnet
```hcl
resource "azurerm_subnet_network_security_group_association" "app_subnet_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.app_nsg_rule_inbound]  
  subnet_id                 = azurerm_subnet.appsubnet.id
  network_security_group_id = azurerm_network_security_group.app_subnet_nsg.id
}
```
#
# Resource-1: Create DBTier Subnet
```hcl
resource "azurerm_subnet" "dbsubnet" {
  name                 = "${azurerm_virtual_network.vnet.name}-${var.db_subnet_name}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.db_subnet_address  
}
```
# Resource-2: Create Network Security Group (NSG)
```hcl
resource "azurerm_network_security_group" "db_subnet_nsg" {
  name                = "${azurerm_subnet.dbsubnet.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
```

# Resource-3: Create NSG Rules
```hcl
## Locals Block for Security Rules
locals {
  db_inbound_ports_map = {
    "100" : "3306",  #MySQL
    "110" : "1433",  #SQL Server
    "120" : "5432"   #PostgreSQL
  } 
}
## NSG Inbound Rule for DBTier Subnets
resource "azurerm_network_security_rule" "db_nsg_rule_inbound" {
  for_each = local.db_inbound_ports_map
  name                        = "Rule-Port-${each.value}"
  priority                    = each.key
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = each.value 
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.db_subnet_nsg.name
}
```
# Resource-4: Associate NSG and Subnet
```hcl
resource "azurerm_subnet_network_security_group_association" "db_subnet_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.db_nsg_rule_inbound]  
  subnet_id                 = azurerm_subnet.dbsubnet.id
  network_security_group_id = azurerm_network_security_group.db_subnet_nsg.id
}
```
#
# Resource-1: Create Bastion / Management Subnet
```hcl
resource "azurerm_subnet" "bastionsubnet" {
  name                 = "${azurerm_virtual_network.vnet.name}-${var.bastion_subnet_name}"  
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.bastion_subnet_address
}
```
# Resource-2: Create Network Security Group (NSG)
```hcl
resource "azurerm_network_security_group" "bastion_subnet_nsg" {
  name                = "${azurerm_subnet.bastionsubnet.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}
```
# Resource-4: Create NSG Rules
```hcl
## Locals Block for Security Rules
locals {
  bastion_inbound_ports_map = {
    "100" : "22",
    "110" : "3389"  #RDP purpose
  } 
}
## NSG Inbound Rule for Bastion / Management Subnets
resource "azurerm_network_security_rule" "bastion_nsg_rule_inbound" {
  for_each = local.bastion_inbound_ports_map
  name                        = "Rule-Port-${each.value}"
  priority                    = each.key
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = each.value 
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.bastion_subnet_nsg.name
}
```
# Resource-4: Associate NSG and Subnet
```hcl
resource "azurerm_subnet_network_security_group_association" "bastion_subnet_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.bastion_nsg_rule_inbound]    
  subnet_id                 = azurerm_subnet.bastionsubnet.id
  network_security_group_id = azurerm_network_security_group.bastion_subnet_nsg.id
}
```
#
# Virtual Network Outputs
```hcl
## Virtual Network Name
output "virtual_network_name" {
  description = "Virtual Network Name"
  value = azurerm_virtual_network.vnet.name
}
## Virtual Network ID
output "virtual_network_id" {
  description = "Virtual Network ID"
  value = azurerm_virtual_network.vnet.id
}

# Subnet Outputs (We will write for one web subnet and rest all we will ignore for now)
## Subnet Name 
output "web_subnet_name" {
  description = "WebTier Subnet Name"
  value = azurerm_subnet.websubnet.name
}

## Subnet ID 
output "web_subnet_id" {
  description = "WebTier Subnet ID"
  value = azurerm_subnet.websubnet.id
}

# Network Security Outputs
## Web Subnet NSG Name 
output "web_subnet_nsg_name" {
  description = "WebTier Subnet NSG Name"
  value = azurerm_network_security_group.web_subnet_nsg.name
}

## Web Subnet NSG ID 
output "web_subnet_nsg_id" {
  description = "WebTier Subnet NSG ID"
  value = azurerm_network_security_group.web_subnet_nsg.id
}
```
# Linux VM Input Variables Placeholder file.
## Web Linux VM Instance Count
```hcl
variable "web_linuxvm_instance_count" {
  description = "Web Linux VM Instance Count"
  type = map(string)
  default = {
    "vm1" = "1022",
    "vm2" = "2022"
  }
}
```
#
# Resource-1: Create Public IP Address for VM (Not Required as we will add Loadbalancer in further step)
```hcl
resource "azurerm_public_ip" "web_linuxvm_publicip" {
  name                = "${local.resource_name_prefix}-web-linuxvm-publicip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku = "Standard"
  #domain_name_label = "app1-vm-${random_string.myrandom.id}"
}
```
#
# Resource-2: Create Network Interface
```hcl
resource "azurerm_network_interface" "web_linuxvm_nic" {
  for_each = var.web_linuxvm_instance_count
  name                = "${local.resource_name_prefix}-web-linuxvm-nic-${each.key}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "web-linuxvm-ip-1"
    subnet_id                     = azurerm_subnet.websubnet.id #10.0.1.0/24
    private_ip_address_allocation = "Dynamic"
    #public_ip_address_id = azurerm_public_ip.web_linuxvm_publicip.id 
  }
}
```
#
## Not Required. Additional layer Security to the VMs level (Not at Vnet level)
# Resource-3 (Optional): Create Network Security Group and Associate to Linux VM Network Interface (Same as )
```hcl
# Resource-1: Create Network Security Group (NSG)
resource "azurerm_network_security_group" "web_vmnic_nsg" {
  name                = "${azurerm_network_interface.web_linuxvm_nic.name}-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

# Resource-2: Associate NSG and Linux VM NIC
resource "azurerm_network_interface_security_group_association" "web_vmnic_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.web_vmnic_nsg_rule_inbound]  
  network_interface_id      = azurerm_network_interface.web_linuxvm_nic.id
  network_security_group_id = azurerm_network_security_group.web_vmnic_nsg.id
}

# Resource-3: Create NSG Rules
## Locals Block for Security Rules
locals {
  web_vmnic_inbound_ports_map = {
    "100" : "80", # If the key starts with a number, you must use the colon syntax ":" instead of "="
    "110" : "443",
    "120" : "22"
  } 
}
## NSG Inbound Rule for WebTier Subnets
resource "azurerm_network_security_rule" "web_vmnic_nsg_rule_inbound" {
  for_each = local.web_vmnic_inbound_ports_map
  name                        = "Rule-Port-${each.value}"
  priority                    = each.key
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = each.value 
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.web_vmnic_nsg.name
}
```

#
# Resource: Azure Linux Virtual Machine
## Locals Block for custom data
```bash
locals {
webvm_custom_data = <<CUSTOM_DATA
#!/bin/sh
#sudo yum update -y
sudo yum install -y httpd
sudo systemctl enable httpd
sudo systemctl start httpd  
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo chmod -R 777 /var/www/html 
sudo echo "Welcome to stacksimplify - WebVM App1 - VM Hostname: $(hostname)" > /var/www/html/index.html
sudo mkdir /var/www/html/app1
sudo echo "Welcome to stacksimplify - WebVM App1 - VM Hostname: $(hostname)" > /var/www/html/app1/hostname.html
sudo echo "Welcome to stacksimplify - WebVM App1 - App Status Page" > /var/www/html/app1/status.html
sudo echo '<!DOCTYPE html> <html> <body style="background-color:rgb(250, 210, 210);"> <h1>Welcome to Stack Simplify - WebVM APP-1 </h1> <p>Terraform Demo</p> <p>Application Version: V1</p> </body></html>' | sudo tee /var/www/html/app1/index.html
sudo curl -H "Metadata:true" --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2020-09-01" -o /var/www/html/app1/metadata.html
CUSTOM_DATA  
}
```

## Resource: Azure Linux Virtual Machine
```hcl
resource "azurerm_linux_virtual_machine" "web_linuxvm" {
  for_each = var.web_linuxvm_instance_count
  name = "${local.resource_name_prefix}-web-linuxvm-${each.key}"
  #computer_name = "web-linux-vm"  # Hostname of the VM (Optional)
  resource_group_name = azurerm_resource_group.rg.name
  location = azurerm_resource_group.rg.location
  size = "Standard_DS1_v2"
  admin_username = "azureuser"
  network_interface_ids = [ azurerm_network_interface.web_linuxvm_nic[each.key].id ]
  admin_ssh_key {
    username = "azureuser"
    public_key = file("${path.module}/ssh-keys/terraform-azure.pub")
  }
  os_disk {
    caching = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "RedHat"
    offer = "RHEL"
    sku = "83-gen2"
    version = "latest"
  }
  #custom_data = filebase64("${path.module}/app-scripts/redhat-webvm-script.sh")    
  custom_data = base64encode(local.webvm_custom_data)  

}
```
#
# Different Outputs with Terraform For Loops
```hcl
# Output List - Single Input to for loop
output "web_linuxvm_private_ip_address_list" {
  description = "Web Linux Virtual Machine Private IP"
  #value = azurerm_linux_virtual_machine.web_linuxvm.private_ip_address
  value = [for vm in azurerm_linux_virtual_machine.web_linuxvm: vm.private_ip_address]
}

# Output Map  - Single Input to for loop
output "web_linuxvm_private_ip_address_map" {
  description = "Web Linux Virtual Machine Private IP"
  #value = azurerm_linux_virtual_machine.web_linuxvm.private_ip_address 
  value = {for vm in azurerm_linux_virtual_machine.web_linuxvm: vm.name => vm.private_ip_address}
}

# Terraform keys() function: keys takes a map and returns a list containing the keys from that map.
output "web_linuxvm_private_ip_address_keys_function" {
  description = "Web Linux Virtual Machine Private IP"
  value = keys({for vm in azurerm_linux_virtual_machine.web_linuxvm: vm.name => vm.private_ip_address})
}
# Terraform values() function: values takes a map and returns a list containing the values of the elements in that map.
output "web_linuxvm_private_ip_address_values_function" {
  description = "Web Linux Virtual Machine Private IP"
  value = values({for vm in azurerm_linux_virtual_machine.web_linuxvm: vm.name => vm.private_ip_address})
}

# Output List - Two Inputs to for loop (here vm is Iterator like "i")
output "web_linuxvm_network_interface_id_list" {
  description = "Web Linux VM Network Interface ID"
  #value = azurerm_network_interface.web_linuxvm_nic.id
  value = [for vm, nic in azurerm_network_interface.web_linuxvm_nic: nic.id ]
}

# Output Map  - Two Inputs to for loop (here vm is Iterator like "i")
output "web_linuxvm_network_interface_id_map" {
  description = "Web Linux VM Network Interface ID"
  #value = azurerm_network_interface.web_linuxvm_nic.id
  value = {for vm, nic in azurerm_network_interface.web_linuxvm_nic: vm => nic.id }
}
```
#
# Bastion Host Linux VM
```hcl
# Resource-1: Create Public IP Address
resource "azurerm_public_ip" "bastion_host_publicip" {
  name                = "${local.resource_name_prefix}-bastion-host-publicip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku = "Standard"
}

# Resource-2: Create Network Interface
resource "azurerm_network_interface" "bastion_host_linuxvm_nic" {
  name                = "${local.resource_name_prefix}-bastion-host-linuxvm-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "bastion-host-ip-1"
    subnet_id                     = azurerm_subnet.bastionsubnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id = azurerm_public_ip.bastion_host_publicip.id 
  }
}

# Resource-3: Azure Linux Virtual Machine - Bastion Host
resource "azurerm_linux_virtual_machine" "bastion_host_linuxvm" {
  name = "${local.resource_name_prefix}-bastion-linuxvm"
  #computer_name = "bastionlinux-vm"  # Hostname of the VM (Optional)
  resource_group_name = azurerm_resource_group.rg.name
  location = azurerm_resource_group.rg.location
  size = "Standard_DS1_v2"
  admin_username = "azureuser"
  network_interface_ids = [ azurerm_network_interface.bastion_host_linuxvm_nic.id ]
  admin_ssh_key {
    username = "azureuser"
    public_key = file("${path.module}/ssh-keys/terraform-azure.pub")
  }
  os_disk {
    caching = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "RedHat"
    offer = "RHEL"
    sku = "83-gen2"
    version = "latest"
  }
  #custom_data = filebase64("${path.module}/app-scripts/redhat-app1-script.sh")    
}
```

#
# Move-ssh-key-to-bastion-host
```hcl
# Create a Null Resource and Provisioners
resource "null_resource" "name" {
  depends_on = [azurerm_linux_virtual_machine.bastion_host_linuxvm]
# Connection Block for Provisioners to connect to Azure VM Instance
  connection {
    type = "ssh"
    host = azurerm_linux_virtual_machine.bastion_host_linuxvm.public_ip_address
    user = azurerm_linux_virtual_machine.bastion_host_linuxvm.admin_username
    private_key = file("${path.module}/ssh-keys/terraform-azure.pem")
  }

## File Provisioner: Copies the terraform-key.pem file to /tmp/terraform-key.pem
  provisioner "file" {
    source      = "ssh-keys/terraform-azure.pem"
    destination = "/tmp/terraform-azure.pem"
  }
## Remote Exec Provisioner: Using remote-exec provisioner fix the private key permissions on Bastion Host
  provisioner "remote-exec" {
    inline = [
      "sudo chmod 400 /tmp/terraform-azure.pem"
    ]
  }
}
```
> # Creation Time Provisioners - By default they are created during resource creations (terraform apply)
> # Destory Time Provisioners - Will be executed during "terraform destroy" command (when = destroy)

#
## Bastion Host Public IP Output
```hcl
output "bastion_host_linuxvm_public_ip_address" {
  description = "Bastion Host Linux VM Public Address"
  value = azurerm_public_ip.bastion_host_publicip.ip_address
}
```


#
# OPTIONAL AZURE BASTION SERVICES (As we use Direct Bastion Servers for the same)
## Optional variables file.
```hcl
variable "bastion_service_subnet_name" {
  description = "Bastion Service Subnet Name"
  default = "AzureBastionSubnet"
}

variable "bastion_service_address_prefixes" {
  description = "Bastion Service Address Prefixes"
  default = ["10.0.101.0/27"]
}
```

# Azure Bastion Service - Resources [If required]
```hcl
## Resource-1: Azure Bastion Subnet
resource "azurerm_subnet" "bastion_service_subnet" {
  name                 = var.bastion_service_subnet_name
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = var.bastion_service_address_prefixes
}

# Resource-2: Azure Bastion Public IP
resource "azurerm_public_ip" "bastion_service_publicip" {
  name                = "${local.resource_name_prefix}-bastion-service-publicip"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Resource-3: Azure Bastion Service Host
resource "azurerm_bastion_host" "bastion_host" {
  name                = "${local.resource_name_prefix}-bastion-service"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  
  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion_service_subnet.id
    public_ip_address_id = azurerm_public_ip.bastion_service_publicip.id
  }
}
```
#
# AZURE LOAD BALANCER
## Resource-1: Create Public IP Address for Azure Load Balancer
```hcl
resource "azurerm_public_ip" "web_lbpublicip" {
  name                = "${local.resource_name_prefix}-lbpublicip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku = "Standard"
  tags = local.common_tags
}
```

## Resource-2: Create Azure Standard Load Balancer (Network)
```hcl
resource "azurerm_lb" "web_lb" {
  name                = "${local.resource_name_prefix}-web-lb"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku = "Standard"
  frontend_ip_configuration {
    name                 = "web-lb-publicip-1"
    public_ip_address_id = azurerm_public_ip.web_lbpublicip.id
  }
}
```
## Resource-3: Create LB Backend Pool
```hcl
resource "azurerm_lb_backend_address_pool" "web_lb_backend_address_pool" {
  name                = "web-backend"
  loadbalancer_id     = azurerm_lb.web_lb.id
}
```
## Resource-6: Associate Network Interface and Standard Load Balancer
### https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface_backend_address_pool_association
```hcl
resource "azurerm_network_interface_backend_address_pool_association" "web_nic_lb_associate" {
  for_each = var.web_linuxvm_instance_count
  network_interface_id    = azurerm_network_interface.web_linuxvm_nic[each.key].id
  ip_configuration_name   = azurerm_network_interface.web_linuxvm_nic[each.key].ip_configuration[0].name
  backend_address_pool_id = azurerm_lb_backend_address_pool.web_lb_backend_address_pool.id
}
```

## Resource-4: Create LB Probe
```hcl
resource "azurerm_lb_probe" "web_lb_probe" {
  name                = "tcp-probe"
  protocol            = "Tcp"
  port                = 80
  loadbalancer_id     = azurerm_lb.web_lb.id
  resource_group_name = azurerm_resource_group.rg.name
}
```
## Resource-5: Create LB Rule
```hcl
resource "azurerm_lb_rule" "web_lb_rule_app1" {
  name                           = "web-app1-rule"
  protocol                       = "Tcp"
  frontend_port                  = 80
  backend_port                   = 80
  frontend_ip_configuration_name = azurerm_lb.web_lb.frontend_ip_configuration[0].name
  backend_address_pool_id        = azurerm_lb_backend_address_pool.web_lb_backend_address_pool.id 
  probe_id                       = azurerm_lb_probe.web_lb_probe.id
  loadbalancer_id                = azurerm_lb.web_lb.id
  resource_group_name            = azurerm_resource_group.rg.name
}
```
#
# Web LoadBalancer Output
```hcl
# LB Public IP
output "web_lb_public_ip_address" {
  description = "Web Load Balancer Public Address"
  value = azurerm_public_ip.web_lbpublicip.ip_address
}

# Load Balancer ID
output "web_lb_id" {
  description = "Web Load Balancer ID."
  value = azurerm_lb.web_lb.id 
}

# Load Balancer Frontend IP Configuration Block
output "web_lb_frontend_ip_configuration" {
  description = "Web LB frontend_ip_configuration Block"
  value = [azurerm_lb.web_lb.frontend_ip_configuration]
}
```
#
# Azure LB Inbound NAT Rule
```hcl
resource "azurerm_lb_nat_rule" "web_lb_inbound_nat_rule_22" {
  depends_on = [azurerm_linux_virtual_machine.web_linuxvm  ] # To effectively handle azurerm provider related dependency bugs during the destroy resources time
  for_each = var.web_linuxvm_instance_count
  name = "${each.key}-ssh-${each.value}-vm-22"
  protocol = "Tcp"
  frontend_port = each.value
  #frontend_port = lookup(var.web_linuxvm_instance_count, each.key)
  backend_port = 22
  frontend_ip_configuration_name = azurerm_lb.web_lb.frontend_ip_configuration[0].name
  resource_group_name = azurerm_resource_group.rg.name
  loadbalancer_id = azurerm_lb.web_lb.id
}
```
# Associate LB NAT Rule and VM Network Interface
```hcl
resource "azurerm_network_interface_nat_rule_association" "web_nic_nat_rule_associate" {
  for_each = var.web_linuxvm_instance_count
  network_interface_id =  azurerm_network_interface.web_linuxvm_nic[each.key].id 
  ip_configuration_name = azurerm_network_interface.web_linuxvm_nic[each.key].ip_configuration[0].name 
  nat_rule_id = azurerm_lb_nat_rule.web_lb_inbound_nat_rule_22[each.key].id
}
```

#
# terraform.tfvars
```hcl
business_divsion = "hr"
environment = "dev"
resource_group_name = "rg"
resource_group_location = "eastus"
vnet_name = "vnet"
vnet_address_space = ["10.1.0.0/16"]

web_subnet_name = "websubnet"
web_subnet_address = ["10.1.1.0/24"]

app_subnet_name = "appsubnet"
app_subnet_address = ["10.1.11.0/24"]

db_subnet_name = "dbsubnet"
db_subnet_address = ["10.1.21.0/24"]

bastion_subnet_name = "bastionsubnet"
bastion_subnet_address = ["10.1.100.0/24"]

bastion_service_subnet_name = "AzureBastionSubnet"
bastion_service_address_prefixes = ["10.1.101.0/27"]

web_linuxvm_instance_count = {
    "vm1" = "1022",
    "vm2" = "2022"
  }
```
