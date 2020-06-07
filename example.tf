# This example terraform requires that you have installed the
# provider from golang/terraform-provider-shakenfist...

provider "shakenfist" {
  address = "http://localhost"
  port    = 13000
}

resource "shakenfist_network" "mynet" {
  name         = "my network"
  netblock     = "192.168.68.0/24"
  provide_dhcp = true
  provide_nat  = true
}

output "mynet_output" {
  value = shakenfist_network.mynet
}
