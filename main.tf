provider "azurerm" {
	alias = "default"
}

#----- Create an elliptical curve based key if requested
resource "null_resource" "ec_key" {
	count = var.enable == true && (var.key_type == "EC" || var.key_type == "EC-HSM") ? 1 : 0

	triggers = {
		key_type = var.key_type
		key = sha1(jsonencode(var.key))
	}
	
	provisioner "local-exec" {
		command = "az keyvault key create --name ${var.key.name} --kty ${var.key_type} --curve ${var.key.size_or_curve} --vault-name ${var.key.vault_name} --ops ${join(" ", var.key.opts)} > /dev/null"
	}
}

#----- Create a RSA based key if requested
resource "null_resource" "rsa_key" {
	count = var.enable == true && (var.key_type == "RSA" || var.key_type == "RSA-HSM") ? 1 : 0

	triggers = {
		key_type = var.key_type
		key = sha1(jsonencode(var.key))
	}
	
	provisioner "local-exec" {
		command = "az keyvault key create --name ${var.key.name} --kty ${var.key_type} --size ${var.key.size_or_curve} --vault-name ${var.key.vault_name} --ops ${join(" ", var.key.opts)} > /dev/null"
	}
}

#----- Get the key attributes used for outputs like version
data "external" "key_data" {
	for_each = var.enable == true ? { "default" = "default" } : {}

	program = [ "sh", "${path.module}/key_data.sh" ]
	
	query = {
		key_name = var.key.name
		vault_name = var.key.vault_name
	}
	
	depends_on = [ null_resource.ec_key, null_resource.rsa_key ]
}
