variable "public_subnet_cidrs" {
  type        = list(string)
  description = "Public Subnet CIDR values"
  default     = ["10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24"]
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "Private Subnet CIDR values"
  default     = ["10.10.4.0/24", "10.10.5.0/24", "10.10.6.0/24"]
}

variable "azs" {
  type        = list(string)
  description = "Availability Zones"
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]
}

variable "region" {
  default = "us-west-2"
}

variable "password" {
  default = "STRonGpassWoRd123"
}

variable "AWS_ACCESS_KEY_ID" {
  default = "AKIAVSAXDMPEGVSMPBWP"
}
variable "AWS_SECRET_ACCESS_KEY" {
  default = "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"
}

variable "zone_id" {

  default = "Z042640935S0EE68HKAO2"

}

variable "domain_name" {
  default = "prod.makeentryleveljobsentrylevel.me"
}