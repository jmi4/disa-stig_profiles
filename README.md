# Example InSpec Profile

This example shows the implementation of an InSpec [profile](../../docs/profiles.rst).

### Testing an inspec profile ###
`inspec exec path/to/controls/profiles.rb --attrs path/to/attrs/file.yml -t ssh://user@ip --password 'password' --sudo`

### disa_stigs ###
#### U_Oracle_Linux_6 ####
 There is a file /controls/test.rb that I have been using to test 1 control at a time. as the full amount of testing takes quite a while due to the rpm control checks.
