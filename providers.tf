terraform {
  cloud {
    organization = "tfo-apj-demos"
    workspaces {
      name = "packer-webhook-mutation"
    }
  }
}