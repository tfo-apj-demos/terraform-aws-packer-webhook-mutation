variable "webhook_hmac_token" {
  description = "HMAC token for webhook signature validation"
  type        = string
  sensitive   = true
}

variable "github_token" {
  description = "GitHub token for API operations"
  type        = string
  sensitive   = true
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  sensitive   = true
  default     = ""
}