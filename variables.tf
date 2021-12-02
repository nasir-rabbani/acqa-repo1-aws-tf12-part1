variable "acqaPrefix" {
    type = string
    default = "acqa-test"
}

# Commenting validation as BAT is using TF .12 and it is TF13 feature
# variable "var1" {
#     type = string
#     default = "acqa-test"
#     validation {
#       condition = (
#         length(var.var1) > 1
#       )
#       error_message = "The length(var1) should be atleast 2 characters."
#   }
# }