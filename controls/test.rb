control "STIG_ID_OL6-00-000385_SEV_CAT-2_VULD-ID_V-50627_audit_directory_permissions_benchmark" do
  title "Audit log directories must have mode 0755 or less permissive."
  desc  "If users can delete audit logs, audit trails can be modified or destroyed."
  impact 0.6

  describe command('grep "^log_file" /etc/audit/auditd.conf|sed "s/^[^/]*//; s/[^/]*$//"|sudo xargs stat -c %a') do
    its('stdout') { should be < 756 }
  end
end
