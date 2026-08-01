terraform {
  required_version = ">= 1.7.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  type      = string
  sensitive = true
}

variable "name" {
  type    = string
  default = "tailbridge-edge"
}

variable "region" {
  type    = string
  default = "nyc3"
}

variable "size" {
  type    = string
  default = "s-1vcpu-1gb"
}

variable "ssh_key_fingerprints" {
  type = list(string)
}

variable "ssh_source_addresses" {
  type        = list(string)
  description = "CIDR ranges that can connect to SSH"
}

provider "digitalocean" {
  token = var.do_token
}

resource "digitalocean_droplet" "edge" {
  image      = "ubuntu-24-04-x64"
  name       = var.name
  region     = var.region
  size       = var.size
  ssh_keys   = var.ssh_key_fingerprints
  ipv6       = true
  monitoring = true

  user_data = <<-CLOUDINIT
    #cloud-config
    package_update: true
    packages:
      - docker.io
      - docker-compose-v2
    runcmd:
      - systemctl enable --now docker
      - sysctl -w net.ipv4.ip_forward=1
      - sysctl -w net.ipv6.conf.all.forwarding=1
      - printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n' > /etc/sysctl.d/99-tailbridge.conf
      - mkdir -p /opt/tailbridge
  CLOUDINIT
}

resource "digitalocean_firewall" "edge" {
  name        = "${var.name}-firewall"
  droplet_ids = [digitalocean_droplet.edge.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_source_addresses
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "41641"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "udp"
    port_range       = "4433"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

output "edge_ipv4" {
  value = digitalocean_droplet.edge.ipv4_address
}

output "edge_ipv6" {
  value = digitalocean_droplet.edge.ipv6_address
}
