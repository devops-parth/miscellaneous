## Step-01: Introduction
- Understand basic Terraform Commands
1. terraform init
2. terraform validate
3. terraform plan
4. terraform apply
5. terraform destroy  \ terraform apply -destroy -auto-approve

# Clean-Up Files
```bash
rm -rf .terraform* 
rm -rf terraform.tfstate*
```
# Get Azure Regions
```bash
az account list-locations -o table
```

- **Pre-Conditions-2:** If not done earlier, complete `az login` via Azure CLI. We are going to use Azure CLI Authentication for Terraform when we use Terraform Commands. 


# Azure CLI Login
```bash
az login
```
# List Subscriptions
```bash
az account list
```
# Set Specific Subscription (if we have multiple subscriptions)
```bash
az account set --subscription="SUBSCRIPTION_ID"
```
## Pre-requisite Note: Create SSH Keys for Azure Linux VM

# Create Folder
```bash
cd terraform-manifests/
mkdir ssh-keys
```
# Create SSH Key
```bash
cd ssh-ekys
ssh-keygen \
    -m PEM \
    -t rsa \
    -b 4096 \
    -C "azureuser@myserver" \
    -f terraform-azure.pem 
```
> Important Note: If you give passphrase during generation, during everytime you login to VM, you also need to provide passphrase.

# List Files
```bash
ls -lrt ssh-keys/
```
# Files Generated after above command 
Public Key: terraform-azure.pem.pub -> Rename as terraform-azure.pub
Private Key: terraform-azure.pem

# Permissions for Pem file
```bash
chmod 400 terraform-azure.pem
```

# SSH Test to VM1
```bash
ssh -i manual-lb.pem -p 1022 azureuser@<LB-Public-IP>
```
# Apache Bench Testing
```bash
ab -t 240 -n 100000 -c 100 http://<LB-Public-IP>/index.html
ab -t 240 -n 100000 -c 100 http://40.121.55.137/index.html
-t Time it need to run
-n Number of Requests
-c concurrency
```

# Resource-1: Create Public IP Address
```hcl
resource "azurerm_public_ip" "web_linuxvm_publicip" {
  name                = "${local.resource_name_prefix}-linuxvm-publicip"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  allocation_method   = "Static"
  sku = "Standard"
  #domain_name_label = "app1-vm-${random_string.myrandom.id}"
}
```

# Delete `.terraform.lock.hcl`
Delete file if exists "`.terraform.lock.hcl`"
```bash
rm -rf .terraform.lock.hcl 
```
# Terraform Providers lock for multiple platforms
```bash
terraform providers lock -platform=windows_amd64 -platform=darwin_amd64 -platform=linux_amd64
```
# tfvars multiple
```bash
-var-file=stage.tfvars -auto-approve
```
##################################################
##################################################

# VARIABLE
```hcl
variable "azure_region" {
  default = "eastus"
  description = "Azure Region where resources to be created"
  type = string
}

variable "lb_inbound_nat_ports" {
  description = "Web LB Inbound NAT Ports List"
  type = list(string)
  default = ["1022", "2022", "3022", "4022", "5022"]
}

variable "web_linuxvm_instance_count" {
  description = "Web Linux VM Instance Count"
  type = map(string)
  default = {
    "vm1" = "1022",
    "vm2" = "2022"
  }
}
```
# terraform.tfvars
```hcl
resource_group_location = "eastus"
vnet_name = "vnet"
vnet_address_space = ["10.1.0.0/16"]
```
# OUTPUT
```hcl
output "azure_resourcegroup_id" {
  description = "My Azure Resource Group ID"
  value = azurerm_resource_group.myrg.id 
}

output "id" {
  value = data.azurerm_resource_group.example.id
}
#Can mention to anything that is not existed in the file
```
# MODULE
```hcl
module "network" {
  source              = "Azure/network/azurerm"
  resource_group_name = azurerm_resource_group.example.name
  address_spaces      = ["10.0.0.0/16", "10.2.0.0/16"]
  subnet_prefixes     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  subnet_names        = ["subnet1", "subnet2", "subnet3"]

  tags = {
    environment = "dev"
    costcenter  = "it"
  }

  depends_on = [azurerm_resource_group.example]
}
```
# ALIAS
```hcl
provider "azurerm" {
  features {
    virtual_machine {
      delete_os_disk_on_deletion = false # This will ensure when the Virtual Machine is destroyed, Disk is not deleted, default is true and we can alter it at provider level
    }
  }
  alias = "provider2-westus"
  #client_id = "XXXX"
  #client_secret = "YYY"
  #environment = "german"
  #subscription_id = "JJJJ"
}

resource "azurerm_resource_group" "myrg2" {
  name = "myrg-2"
  location = "West US"
  provider = azurerm.provider2-westus
}
```
# TAGS
```hcl
resource "azurerm_storage_account" "mysa" {
  name                     = "mysa${random_string.myrandom.id}"
  resource_group_name      = azurerm_resource_group.myrg1.name
  location                 = azurerm_resource_group.myrg1.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_encryption_source = "Microsoft.Storage"

  tags = {
    environment = "staging"
  }
}
```
# LOCALS
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

resource "azurerm_resource_group" "rg" {
  # name = "${local.resource_name_prefix}-${var.resource_group_name}"
  name = "${local.resource_name_prefix}-${var.resource_group_name}-${random_string.myrandom.id}"
  location = var.resource_group_location
  tags = local.common_tags
}
```
# FOR EACH
## Type 1
```hcl
locals {
  web_inbound_ports_map = {
    "100" : "80", # If the key starts with a number, you must use the colon syntax ":" instead of "="
    "110" : "443",
    "120" : "22"
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
## Type 2
```hcl
variable "web_linuxvm_instance_count" {
  description = "Web Linux VM Instance Count"
  type = map(string)
  default = {
    "vm1" = "1022",
    "vm2" = "2022"
  }
}

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

# Type 3
```hcl
variable "web_vmss_nsg_inbound_ports" {
  description = "Web VMSS NSG Inbound Ports"
  type = list(string)
  default = [22, 80, 443]
}

# Create Network Security Group using Terraform Dynamic Blocks
resource "azurerm_network_security_group" "web_vmss_nsg" {
  name                = "${local.resource_name_prefix}-web-vmss-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  dynamic "security_rule" {
    for_each = var.web_vmss_nsg_inbound_ports
    content {
      name                       = "inbound-rule-${security_rule.key}"
      description                = "Inbound Rule ${security_rule.key}"    
      priority                   = sum([100, security_rule.key])
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = security_rule.value
      source_address_prefix      = "*"
      destination_address_prefix = "*"      
    }
  }

}
```
# TYPE 4
```hcl
locals {
  httpd_conf_files = ["app1.conf"]
}
# Resource-3: httpd conf files upload to httpd-files-container
resource "azurerm_storage_blob" "httpd_files_container_blob" {
  for_each = toset(local.httpd_conf_files)
  name                   = each.value
  storage_account_name   = azurerm_storage_account.storage_account.name
  storage_container_name = azurerm_storage_container.httpd_files_container.name
  type                   = "Block"
  source = "${path.module}/app-scripts/${each.value}"
}
```

# CUSTOM DATA
```hcl
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


# Resource: Azure Linux Virtual Machine
resource "azurerm_linux_virtual_machine" "web_linuxvm" {
  name = "${local.resource_name_prefix}-web-linuxvm"
  #computer_name = "web-linux-vm" # Hostname of the VM (Optional)
  resource_group_name = azurerm_resource_group.rg.name
  location = azurerm_resource_group.rg.location 
  size = "Standard_DS1_v2"
  admin_username = "azureuser"
  network_interface_ids = [ azurerm_network_interface.web_linuxvm_nic.id ]
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
# DEPENDS ON
```hcl
# Resource-3: Associate NSG and Subnet
resource "azurerm_subnet_network_security_group_association" "web_subnet_nsg_associate" {
  depends_on = [ azurerm_network_security_rule.web_nsg_rule_inbound] # Every NSG Rule Association will disassociate NSG from Subnet and Associate it, so we associate it only after NSG is completely created - Azure Provider Bug https://github.com/terraform-providers/terraform-provider-azurerm/issues/354  
  subnet_id                 = azurerm_subnet.websubnet.id
  network_security_group_id = azurerm_network_security_group.web_subnet_nsg.id
}
```
# NULL RESOURCE & PROVISIONERS
### Provisioner: file, remote-exec
### path.module
```hcl
# Create a Null Resource and Provisioners
resource "null_resource" "null_copy_ssh_key_to_bastion" {
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
    source = "ssh-keys/terraform-azure.pem"
    destination = "/tmp/terraform-azure.pem"
  }
## Remote Exec Provisioner: Using remote-exec provisioner fix the private key permissions on Bastion Host
  provisioner "remote-exec" {
    inline = [
      "sudo chmod 400 /tmp/terraform-azure.pem"
    ]
  }
}

# Creation Time Provisioners - By default they are created during resource creations (terraform apply)
# Destory Time Provisioners - Will be executed during "terraform destroy" command (when = destroy)
```
# List [Index]
```hcl
resource "azurerm_network_interface" "web_linuxvm_nic" {
  name                = "${local.resource_name_prefix}-web-linuxvm-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "web-linuxvm-ip-1"
    subnet_id                     = azurerm_subnet.websubnet.id
    private_ip_address_allocation = "Dynamic"
    #public_ip_address_id = azurerm_public_ip.web_linuxvm_publicip.id 
  }
}

resource "azurerm_network_interface_backend_address_pool_association" "web_nic_lb_associate" {
  network_interface_id = azurerm_network_interface.web_linuxvm_nic.id 
  ip_configuration_name = azurerm_network_interface.web_linuxvm_nic.ip_configuration[0].name
  backend_address_pool_id = azurerm_lb_backend_address_pool.web_lb_backend_address_pool.id   
}


resource "azurerm_network_interface_nat_rule_association" "web_nic_nat_rule_associate" {
  count = var.web_linuxvm_instance_count
  network_interface_id  = element(azurerm_network_interface.web_linuxvm_nic[*].id, count.index) 
  ip_configuration_name = element(azurerm_network_interface.web_linuxvm_nic[*].ip_configuration[0].name, count.index) 
  nat_rule_id           = element(azurerm_lb_nat_rule.web_lb_inbound_nat_rule_22[*].id, count.index)
}
```
# ELEMENTS
```hcl
resource "azurerm_network_interface_nat_rule_association" "web_nic_nat_rule_associate" {
  count = var.web_linuxvm_instance_count
  network_interface_id  = element(azurerm_network_interface.web_linuxvm_nic[*].id, count.index) 
  ip_configuration_name = element(azurerm_network_interface.web_linuxvm_nic[*].ip_configuration[0].name, count.index) 
  nat_rule_id           = element(azurerm_lb_nat_rule.web_lb_inbound_nat_rule_22[*].id, count.index)
}

> element(["a", "b", "c"], 3)
    >> a
```
# COUNT
```hcl
resource "azurerm_linux_virtual_machine" "web_linuxvm" {
  count = var.web_linuxvm_instance_count
  name = "${local.resource_name_prefix}-web-linuxvm-${count.index}"
  #computer_name = "web-linux-vm"  # Hostname of the VM (Optional)
  resource_group_name = azurerm_resource_group.rg.name
  location = azurerm_resource_group.rg.location
  size = "Standard_DS1_v2"
  admin_username = "azureuser"
  network_interface_ids = [element(azurerm_network_interface.web_linuxvm_nic[*].id, count.index)]
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
```
# BACKEND
```hcl
# Type1
  backend "azurerm" {
    resource_group_name   = "terraform-storage-rg"
    storage_account_name  = "terraformstate201"
    container_name        = "tfstatefiles"
    key                   = "project-1-eastus2-terraform.tfstate"
  }  

# Type2
  data "terraform_remote_state" "project1_eastus2" {
  backend = "azurerm"
  config = {
    resource_group_name   = "terraform-storage-rg"
    storage_account_name  = "terraformstate201"
    container_name        = "tfstatefiles"
    key                   = "project-1-eastus2-terraform.tfstate"
  }
}
```
# KEY VAULT
```hcl
# Datasource-1: To get Azure Tenant Id
data "azurerm_client_config" "current" {}

# Resource-1: Azure Key Vault
resource "azurerm_key_vault" "keyvault" {
  name                        = "${var.business_divsion}${var.environment}keyvault${random_string.myrandom.id}"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  enabled_for_template_deployment = true
  sku_name = "premium"
}


# Resource-2: Azure Key Vault Default Policy
resource "azurerm_key_vault_access_policy" "key_vault_default_policy" {
  key_vault_id = azurerm_key_vault.keyvault.id
  tenant_id = data.azurerm_client_config.current.tenant_id
  object_id = data.azurerm_client_config.current.object_id
  lifecycle {
    create_before_destroy = true
  }  
  certificate_permissions = [
    "Backup", "Create", "Delete", "DeleteIssuers", "Get", "GetIssuers", "Import", "List", "ListIssuers", "ManageContacts", "ManageIssuers", "Purge", "Recover", "Restore", "SetIssuers", "Update"
  ]
  key_permissions = [
    "Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge", "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey"
  ]
  secret_permissions = [
    "Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set"
  ]
  storage_permissions = [
    "Backup", "Delete", "DeleteSAS", "Get", "GetSAS", "List", "ListSAS", "Purge", "Recover", "RegenerateKey", "Restore", "Set", "SetSAS", "Update"
  ]

}


# Resource-3: Add a managed ID to your Key Vault access policy (Resource: azurerm_key_vault_access_policy)
resource "azurerm_key_vault_access_policy" "appag_key_vault_access_policy" {
  key_vault_id = azurerm_key_vault.keyvault.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_user_assigned_identity.appag_umid.principal_id
  secret_permissions = [
    "Get",
  ]
}


# Resource-4: Import the SSL certificate into Key Vault and store the certificate SID in a variable
resource "azurerm_key_vault_certificate" "my_cert_1" {
  depends_on = [azurerm_key_vault_access_policy.key_vault_default_policy]
  name         = "my-cert-1"
  key_vault_id = azurerm_key_vault.keyvault.id

  certificate {
    contents = filebase64("${path.module}/ssl-self-signed/httpd.pfx")
    password = "kalyan"
  }
  
  certificate_policy {
    issuer_parameters {
      name = "Unknown"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }
    lifetime_action {
      action {
        action_type = "EmailContacts"        
      }
      trigger {
        days_before_expiry = 10
      }
    }
  }

}

# Output Values
output "azurerm_key_vault_certificate_id" {
  value = azurerm_key_vault_certificate.my_cert_1.id
}

output "azurerm_key_vault_certificate_secret_id" {
  value = azurerm_key_vault_certificate.my_cert_1.secret_id
}
output "azurerm_key_vault_certificate_version" {
  value = azurerm_key_vault_certificate.my_cert_1.version
}
```

# MYSQL SERVER
```hcl
# Resource-1: Azure MySQL Server
resource "azurerm_mysql_server" "mysql_server" {
  name                = "${local.resource_name_prefix}-${var.mysql_db_name}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  administrator_login          = var.mysql_db_username
  administrator_login_password = var.mysql_db_password

  #sku_name   = "B_Gen5_2" # Basic Tier - Azure Virtual Network Rules not supported
  sku_name   = "GP_Gen5_2" # General Purpose Tier - Supports Azure Virtual Network Rules
  storage_mb = 5120
  version    = "8.0"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = false
  infrastructure_encryption_enabled = false
  public_network_access_enabled     = true
  ssl_enforcement_enabled           = false
  ssl_minimal_tls_version_enforced  = "TLSEnforcementDisabled" 

}

# Resource-2: Azure MySQL Database / Schema
resource "azurerm_mysql_database" "webappdb" {
  name                = var.mysql_db_schema
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_mysql_server.mysql_server.name
  charset             = "utf8"
  collation           = "utf8_unicode_ci"
}

# Resource-3: Azure MySQL Firewall Rule - Allow access from Bastion Host Public IP
resource "azurerm_mysql_firewall_rule" "mysql_fw_rule" {
  name                = "allow-access-from-bastionhost-publicip"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_mysql_server.mysql_server.name
  start_ip_address    = azurerm_public_ip.bastion_host_publicip.ip_address
  end_ip_address      = azurerm_public_ip.bastion_host_publicip.ip_address
}

# Resource-4: Azure MySQL Virtual Network Rule
resource "azurerm_mysql_virtual_network_rule" "mysql_virtual_network_rule" {
  name                = "mysql-vnet-rule"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_mysql_server.mysql_server.name
  subnet_id           = azurerm_subnet.websubnet.id
}

# Output Values
output "mysql_server_fqdn" {
  description = "MySQL Server FQDN"
  value = azurerm_mysql_server.mysql_server.fqdn
}
```
