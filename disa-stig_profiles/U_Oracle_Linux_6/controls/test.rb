control "STIG_ID_OL6-00-000253_SEV_CAT-2_VULD-ID_V-50819_ldap_certs_benchmark" do
  title "The LDAP client must use a TLS connection using trust certificates signed by the site CA."
  desc  "The tls_cacertdir or tls_cacertfile directives are required when tls_checkpeer is configured (which is the default for openldap versions 2.1 and up). These directives define the path to the trust certificates signed by the site CA."
  impact 0.6

  only_if do
    file('/etc/pam_ldap.conf').exist?
  end

  describe command('grep cert /etc/pam_ldap.conf ') do
    its('stdout') { should match /^ssl start_tls/i }
  end
end
