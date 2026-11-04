# network.tf - Danicoy's Bubble: three-tier network design (design-as-code)
## Local sandbox project. Intended for `terraform fmt` and `terraform validate`.
# It is a reference design and is not meant to be applied to a live environment.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  # Provider v4 expects a subscription_id (here or via ARM_SUBSCRIPTION_ID)
  # when planning or applying. It is not needed for `terraform validate`.
}

locals {
  environment = "sandbox"
  zone        = "core"
  location    = "eastus"
}

resource "azurerm_resource_group" "main" {
  name     = "rg-bubble-${local.zone}-${local.environment}"
  location = local.location
}

# Parent network: 10.0.0.0/16 (65,536 addresses)
resource "azurerm_virtual_network" "primary_vnet" {
  name                = "bubble-${local.zone}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.0.0.0/16"]
}

# Tier 1: web / ingress (10.0.1.0/24 - 251 usable addresses)
resource "azurerm_subnet" "web_tier" {
  name                 = "snet-web"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.primary_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Tier 2: application / business logic (10.0.2.0/24 - 251 usable addresses)
resource "azurerm_subnet" "app_tier" {
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.primary_vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

# Tier 3: isolated database (10.0.3.0/24 - 251 usable addresses)
resource "azurerm_subnet" "db_tier" {
  name                 = "snet-db"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.primary_vnet.name
  address_prefixes     = ["10.0.3.0/24"]
}

# Network security group: zero-trust inbound controls for the database tier.
# Only the application tier may reach the database port; everything else is denied.
resource "azurerm_network_security_group" "db_tier_nsg" {
  name                = "nsg-database-protection"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "Allow-App-Tier-To-DB"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433" # change to match your database engine
    source_address_prefix      = "10.0.2.0/24"
    destination_address_prefix = "10.0.3.0/24"
  }

  security_rule {
    name                       = "Deny-All-Other-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "10.0.3.0/24"
  }
}

resource "azurerm_subnet_network_security_group_association" "db" {
  subnet_id                 = azurerm_subnet.db_tier.id
  network_security_group_id = azurerm_network_security_group.db_tier_nsg.id
}
