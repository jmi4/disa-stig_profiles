# encoding: utf-8
# copyright: 2015, The Authors
# license: All rights reserved
#
# Notes
# There are some stigs that require an administrator interview such as:
# OL6-00-000524/V-50519, OL6-00-000505/V-50613, OL6-00-000504/V-50615
# OL6-00-000349/V-50639
#
# Not a good candidate for inspec at this time:
# OL6-00-000011/V-50695
#
# I will have these commented out below, can they are configured to dectect results based on common enterprise setups.
#
# Attributes
csd = attribute('cross_system_domain', default: false)

title 'DISA-STIG_RHEL-6'

control "STIG_ID_OL6-00-000526_SEV_CAT-3_VULD-ID_V-50515_autofs_benchmark" do
  title "Automated file system mounting tools must not be enabled unless needed."
  desc  "All filesystems that are required for the successful operation of the system should be explicitly listed in /etc/fstab by an administrator. New filesystems should not be arbitrarily introduced via the automounter."
  impact 0.3

  only_if do
    command('/etc/init.d/autofs').exist?
  end

  describe service('autofs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000525_SEV_CAT-3_VULD-ID_V-50517_auditing_benchmark" do
  title "Auditing must be enabled at boot by setting a kernel parameter."
  desc  "Each process on the system carries an auditable flag which indicates whether its activities can be audited. Although auditd takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot."
  impact 0.3

  describe file('/etc/grub.conf') do
    it { should be_file }
    its('content') { should match /audit=1/ }
  end
end

# This may need to be commented out as it really is to be an interview with a System Admin
# to discuss account managment, however for winbind account management this should work.
# control "STIG_ID_OL6-00-000524_SEV_CAT-2_VULD-ID_V-50519_auditing_benchmark" do
#   title "The system must provide automated support for account management functions."
#   desc  "A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight."
#   impact 0.6

#   describe file('/etc/nsswitch.conf') do
#     it { should be_file }
#     its('content') { should match /^passwd:\s+files\s+winbind/ }
#     its('content') { should match /^shadow:\s+files\s+winbind/ }
#     its('content') { should match /^group:\s+files\s+winbind/ }
#   end
# end

control "STIG_ID_OL6-00-000523_SEV_CAT-2_VULD-ID_V-50521_auditing_benchmark" do
  title "The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets."
  desc  "In ip6tables the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to DROP implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted."
  impact 0.6

  only_if do
    file('/etc/sysconfig/ip6tables').exist?
  end

  describe command('grep -i ":input" /etc/sysconfig/ip6tables') do
    its('stdout') { should match /DROP/i }
  end
end

control "STIG_ID_OL6-00-000522_SEV_CAT-2_VULD-ID_V-50523_ipv6iptables-input_benchmark" do
  title "Audit log files must be group-owned by root."
  desc  "If non-privileged users can write to audit logs, audit trails can be modified or destroyed."
  impact 0.6

  only_if do
    file('/etc/sysconfig/ip6tables').exist?
  end

  describe command('grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|sudo xargs stat -c %G') do
    its('stdout') { should match /root/i }
  end
end

control "STIG_ID_OL6-00-000521_SEV_CAT-2_VULD-ID_V-50525_postfix-aliases_benchmark" do
  title "The mail system must forward all mail for root to one or more system administrators."
  desc  "A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues. These messages must be forwarded to at least one monitored email address."
  impact 0.6

  describe file('/etc/aliases') do
    it { should be_file }
    its('content') { should match /postmaster:\s+root/i }
  end
end

control "STIG_ID_OL6-00-000003_SEV_CAT-3_VULD-ID_V-50529_/var/log_benchmark" do
  title "The system must use a separate file system for /var/log."
  desc  "Placing /var/log in its own partition enables better separation between log files and other files in /var/."
  impact 0.3

  describe command('mount | grep "on /var/log "') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000001_SEV_CAT-3_VULD-ID_V-50533_/var/tmp_benchmark" do
  title "The system must use a separate file system for /tmp."
  desc  "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it."
  impact 0.3

  describe command('mount | grep "on /tmp "') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000519_SEV_CAT-3_VULD-ID_V-50535_auditing_benchmark" do
  title "The system package management tool must verify contents of all files associated with packages."
  desc  "The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system."
  impact 0.3

  describe command('rpm -Va | awk \'$1 ~ /..5/ && $2 != "c"\'') do
    its('stdout') { should_not match /^.+/ }
  end
end

control "STIG_ID_OL6-00-000002_SEV_CAT-3_VULD-ID_V-50537_/var_benchmark" do
  title "The system package management tool must verify permissions on all files and directories associated with packages."
  desc  "Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated."
  impact 0.3

  describe command('mount | grep "on /var "') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000518_SEV_CAT-3_VULD-ID_V-50539_package_managment_permissions_benchmark" do
  title "The system package management tool must verify permissions on all files and directories associated with packages."
  desc  "Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated."
  impact 0.3

  describe command('rpm -Va | grep \'^.M\'') do
    its('stdout') { should_not match /^.M/ }
  end
end

control "STIG_ID_OL6-00-000202_SEV_CAT-2_VULD-ID_V-50545_audit_configuration_benchmark" do
  title "The audit system must be configured to audit the loading and unloading of dynamic kernel modules."
  desc  "The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel."
  impact 0.6

  describe command('egrep -e "(-w |-F path=)/sbin/insmod" /etc/audit/audit.rules') do
    its('stdout') { should match /-w\s+\/sbin\/insmod\s+-p\s+x\s+-k\s+module.+/i }
  end
  describe command('egrep -e "(-w |-F path=)/sbin/rmmod" /etc/audit/audit.rules') do
    its('stdout') { should match /-w\s+\/sbin\/rmmod\s+-p\s+x\s+-k\s+module.+/i }
  end
  describe command('egrep -e "(-w |-F path=)/sbin/modprobe" /etc/audit/audit.rules') do
    its('stdout') { should match /-w\s+\/sbin\/modprobe\s+-p\s+x\s+-k\s+module.+/i }
  end
  describe command('grep -w "init_module" /etc/audit/audit.rules ') do
    its('stdout') { should match /^.+/ }
  end
end

control "STIG_ID_OL6-00-000203_SEV_CAT-2_VULD-ID_V-50547_xinetd_running_benchmark" do
  title "The xinetd service must be disabled if no network services utilizing it are enabled."
  desc  "The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself."
  impact 0.6

  describe service('xinetd') do
    it { should_not be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000204_SEV_CAT-3_VULD-ID_V-50549_xinetd_installed_benchmark" do
  title "The xinetd service must be uninstalled if no network services utilizing it are enabled."
  desc  "Removing the xinetd package decreases the risk of the xinetd service's accidental (or intentional) activation."
  impact 0.3

  describe command('rpm -q xinetd') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000206_SEV_CAT-1_VULD-ID_V-50551_telnet-server_installed_benchmark" do
  title "The telnet-server package must not be installed."
  desc  "Removing the telnet-server package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation."
  impact 1.0

  describe command('rpm -q telnet-server') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000211_SEV_CAT-1_VULD-ID_V-50553_telnet_installed_benchmark" do
  title "The telnet daemon must not be running."
  desc  "The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks."
  impact 1.0

  describe service('telnet') do
    it { should_not be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000213_SEV_CAT-1_VULD-ID_V-50555_rsh-server_installed_benchmark" do
  title "The rsh-server package must not be installed."
  desc  "The rsh-server package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation."
  impact 1.0

  describe command('rpm -q rsh-server') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000214_SEV_CAT-1_VULD-ID_V-50557_rsh-server_benchmark" do
  title "The rshd service must not be running."
  desc  "The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network."
  impact 1.0

  describe service('rsh') do
    it { should_not be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000216_SEV_CAT-1_VULD-ID_V-50559_rexec_benchmark" do
  title "The rexecd service must not be running."
  desc  "The rexec service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network."
  impact 1.0

  describe service('rexec') do
    it { should_not be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000218_SEV_CAT-1_VULD-ID_V-50561_rlogin_benchmark" do
  title "The rlogind service must not be running."
  desc  "The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network."
  impact 1.0

  describe service('rlogin') do
    it { should_not be_installed }
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000220_SEV_CAT-2_VULD-ID_V-50563_ypserv_installed_benchmark" do
  title "The ypserv package must not be installed."
  desc  "Removing the ypserv package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services."
  impact 0.6

  describe command('rpm -q ypserv') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000221_SEV_CAT-2_VULD-ID_V-50565_ypbind_benchmark" do
  title "The ypbind service must not be running."
  desc  "The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network."
  impact 0.6

  describe service('ypbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000222_SEV_CAT-2_VULD-ID_V-50567_tftp-server_installed_benchmark" do
  title "The tftp-server package must not be installed unless required."
  desc  "Removing the tftp-server package decreases the risk of the accidental (or intentional) activation of tftp services."
  impact 0.6

  describe command('tftp-server') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000223_SEV_CAT-2_VULD-ID_V-50569_tftp_benchmark" do
  title "The TFTP service must not be running."
  desc  "Disabling the tftp service ensures the system is not acting as a tftp server, which does not provide encryption or authentication."
  impact 0.6

  describe service('tftp') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000224_SEV_CAT-2_VULD-ID_V-50571_tftp_benchmark" do
  title "The cron service must be running."
  desc  "Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential."
  impact 0.6

  describe service('crond') do
    it { should be_installed}
    it { should be_enabled }
    it { should be_running }
  end
end

control "STIG_ID_OL6-00-000227_SEV_CAT-1_VULD-ID_V-50573_SSH-v2_benchmark" do
  title "The SSH daemon must be configured to use only the SSHv2 protocol."
  desc  "SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used."
  impact 1.0

  describe command('grep Protocol /etc/ssh/sshd_config') do
    its('stdout') { should match /^Protocol\s+2/ }
  end
end

control "STIG_ID_OL6-00-000230_SEV_CAT-3_VULD-ID_V-50575_SSH_Alive_timeout_benchmark" do
  title "The SSH daemon must set a timeout interval on idle sessions."
  desc  "Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another."
  impact 0.3

  describe command('grep ClientAliveInterval /etc/ssh/sshd_config') do
    its('stdout') { should match /^ClientAliveInterval\s+900/ }
  end
end

control "STIG_ID_OL6-00-000231_SEV_CAT-3_VULD-ID_V-50577_SSH_Alive-count_benchmark" do
  title "The SSH daemon must set a timeout count on idle sessions."
  desc  "This ensures a user login will be terminated as soon as the ClientAliveCountMax is reached."
  impact 0.3

  describe command('grep ClientAliveCountMax /etc/ssh/sshd_config') do
    its('stdout') { should match /^ClientAliveCountMax\s+0/ }
  end
end

control "STIG_ID_OL6-00-000234_SEV_CAT-2_VULD-ID_V-50579_SSH_ignore_rhosts_benchmark" do
  title "The SSH daemon must ignore .rhosts files."
  desc  "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts."
  impact 0.6

  describe command('grep -i IgnoreRhosts /etc/ssh/sshd_config') do
    its('stdout') { should match /^IgnoreRhosts\s+yes/i }
  end
end

control "STIG_ID_OL6-00-000236_SEV_CAT-2_VULD-ID_V-50581_SSH_ignore_host-base_auth_benchmark" do
  title "The SSH daemon must not allow host-based authentication."
  desc  "SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts."
  impact 0.6

  describe command('grep -i HostbasedAuthentication /etc/ssh/sshd_config') do
    its('stdout') { should match /^HostbasedAuthentication\s+no/i }
  end
end

control "STIG_ID_OL6-00-000517_SEV_CAT-3_VULD-ID_V-50591_RPM_group-ownership_benchmark" do
  title "The system package management tool must verify group-ownership on all files and directories associated with packages."
  desc  "Group-ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated."
  impact 0.3

  describe command('rpm -Va | grep "^......G"') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000516_SEV_CAT-3_VULD-ID_V-50593_RPM_ownership_benchmark" do
  title "The system package management tool must verify ownership on all files and directories associated with packages."
  desc  "Ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated."
  impact 0.3

  describe command('rpm -Va | grep "^.....U"') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000515_SEV_CAT-3_VULD-ID_V-50595_NFS_all-squash_benchmark" do
  title "The NFS server must not have the all_squash option enabled."
  desc  "The all_squash option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID."
  impact 0.3

  describe command('grep all_squash /etc/exports') do
    its('exit_status') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000511_SEV_CAT-2_VULD-ID_V-50599_SSH_audit_disk_errors_benchmark" do
  title "The audit system must take appropriate action when there are disk errors on the audit storage volume."
  desc  "Taking appropriate action in case of disk errors will minimize the possibility of losing audit records."
  impact 0.6

  describe command('grep disk_error_action /etc/audit/auditd.conf') do
    its('stdout') { should_not match /suspend/i }
    its('stdout') { should_not match /ignore/i }
  end
end

control "STIG_ID_OL6-00-000510_SEV_CAT-2_VULD-ID_V-50601_SSH_audit_disk_full_benchmark" do
  title "The audit system must take appropriate action when the audit storage volume is full."
  desc  "Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records."
  impact 0.6

  describe command('grep disk_full_action /etc/audit/auditd.conf') do
    its('stdout') { should_not match /suspend/i }
    its('stdout') { should_not match /ignore/i }
  end
end

control "STIG_ID_OL6-00-000509_SEV_CAT-3_VULD-ID_V-50603_using_syslog_benchmark" do
  title "The system must forward audit records to the syslog service."
  desc  "The auditd service does not include the ability to send audit records to a centralized server for management directly. It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server."
  impact 0.3

  describe command('grep active /etc/audisp/plugins.d/syslog.conf') do
    its('stdout') { should match /^active\s+=\s+yes/i }
  end
end

control "STIG_ID_OL6-00-000508_SEV_CAT-3_VULD-ID_V-50607_GConf2-screensaver_benchmark" do
  title "The system must allow locking of graphical desktop sessions."
  desc  "The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily."
  impact 0.3

  only_if do
    file('/usr/bin/gconftool-2').exist?
  end

  describe command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver') do
    its('stdout') { should match /.+/ }
  end
end

control "STIG_ID_OL6-00-000507_SEV_CAT-2_VULD-ID_V-50609_SSH_print_last_log_benchmark" do
  title "The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh."
  desc  "Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators."
  impact 0.6

  describe command('grep -i "^PrintLastLog" /etc/ssh/sshd_config') do
    its('stdout') { should match /^PrintLastLog\s+yes/i }
  end
end

# Requires System Administrator interview
# control "STIG_ID_OL6-00-000505_SEV_CAT-2_VULD-ID_V-50613_OS_backups_process_running_benchmark" do
#   title "The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives."
#   desc  "Operating system backup is a critical step in maintaining data assurance and availability. System-level information includes system-state information, operating system and application software, and licenses. Backups must be consistent with organizational recovery time and recovery point objectives."
#   impact 0.6

#   describe command('rpm -qa |grep -i backups |grep -v grep') do
#     its('stdout') { should match /backup/i }
#   end
# end

# Requires System Administrator interview
# control "STIG_ID_OL6-00-000504_SEV_CAT-2_VULD-ID_V-50615_OS_backups_process_running_benchmark" do
#   title "The operating system must conduct backups of user-level information contained in the operating system per organization defined frequency to conduct backups consistent with recovery time and recovery point objectives."
#   desc  "Operating system backup is a critical step in maintaining data assurance and availability. User-level information is data generated by information system and/or application users. Backups shall be consistent with organizational recovery time and recovery point objectives."
#   impact 0.6

#   describe command('rpm -qa |grep -i backups |grep -v grep') do
#     its('stdout') { should match /backup/i }
#   end
# end

control "STIG_ID_OL6-00-000503_SEV_CAT-2_VULD-ID_V-50617_usb_drives_depricated_benchmark" do
  title "The operating system must enforce requirements for the connection of mobile devices to operating systems."
  desc  "USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled."
  impact 0.6

  only_if do
    file('/etc/modprobe.conf').exist?
  end

  describe command('grep -r usb-storage /etc/modprobe.conf') do
    its('stdout') { should match /.+/ }
  end
end

control "STIG_ID_OL6-00-000503_SEV_CAT-2_VULD-ID_V-50617_usb_drives_benchmark" do
  title "The operating system must enforce requirements for the connection of mobile devices to operating systems."
  desc  "USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled."
  impact 0.6

  describe command('grep -r usb-storage /etc/modprobe.d') do
    its('stdout') { should match /usb-storage/ }
  end
end

control "STIG_ID_OL6-00-000086_SEV_CAT-2_VULD-ID_V-50621_net_secure_redirects_benchmark" do
  title "The system must not accept ICMPv4 secure redirect packets on any interface."
  desc  "Accepting secure ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required."
  impact 0.6

  describe command('sysctl net.ipv4.conf.all.secure_redirects') do
    its('stdout') { should match /^net.ipv4.conf.all.secure_redirects\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000088_SEV_CAT-3_VULD-ID_V-50625_net_secure_redirects_benchmark" do
  title "The system must log Martian packets."
  desc  "The presence of martian packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected."
  impact 0.3

  describe command('sysctl net.ipv4.conf.all.log_martians') do
    its('stdout') { should match /^net.ipv4.conf.all.log_martians\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000385_SEV_CAT-2_VULD-ID_V-50627_audit_directory_permissions_benchmark" do
  title "Audit log directories must have mode 0755 or less permissive."
  desc  "If users can delete audit logs, audit trails can be modified or destroyed."
  impact 0.6

  describe command('grep "^log_file" /etc/audit/auditd.conf|sed "s/^[^/]*//; s/[^/]*$//"|sudo xargs stat -c %a') do
    its('stdout.to_i') { should be <= 755 }
  end
end

control "STIG_ID_OL6-00-000384_SEV_CAT-2_VULD-ID_V-50629_audit_directory_owner_benchmark" do
  title "Audit log files must be owned by root."
  desc  "If non-privileged users can write to audit logs, audit trails can be modified or destroyed."
  impact 0.6

  describe command('grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|sudo xargs stat -c %U') do
    its('stdout') { should match /root/ }
  end
end

control "STIG_ID_OL6-00-000383_SEV_CAT-2_VULD-ID_V-50631_audit_log_permissions_benchmark" do
  title "Audit log files must have mode 0640 or less permissive."
  desc  "If users can write to audit logs, audit trails can be modified or destroyed."
  impact 0.6

  describe command('grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|sudo xargs stat -c %a') do
    its('stdout.to_i') { should be <= 640 }
  end
end

control "STIG_ID_OL6-00-000357_SEV_CAT-2_VULD-ID_V-50635_pam_login_failures_benchmark" do
  title "The system must disable accounts after excessive login failures within a 15-minute interval."
  desc  "Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks."
  impact 0.6

  describe command('grep pam_faillock /etc/pam.d/system-auth | awk -F= \'$1=="fail_interval"{print $2}\' RS=\' \'|head -1') do
    its('stdout.to_i') { should be >= 900 }
    its('stdout') { should match /\d+/ }
  end

  describe command('grep pam_faillock /etc/pam.d/password-auth | awk -F= \'$1=="fail_interval"{print $2}\' RS=\' \'|head -1') do
    its('stdout.to_i') { should be >= 900 }
    its('stdout') { should match /\d+/ }
  end
end

control "STIG_ID_OL6-00-000356_SEV_CAT-2_VULD-ID_V-50637_pam_lockout_time_benchmark" do
  title "The system must require administrator action to unlock an account locked by excessive failed login attempts."
  desc  "Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations."
  impact 0.6

  describe command('grep pam_faillock /etc/pam.d/system-auth | awk -F= \'$1=="unlock_time"{print $2}\' RS=\' \' |head -1') do
    its('stdout.to_i') { should be <= 604800 }
    its('stdout') { should match /\d+/ }
  end

  describe command('grep pam_faillock /etc/pam.d/password-auth | awk -F= \'$1=="unlock_time"{print $2}\' RS=\' \' |head -1') do
    its('stdout.to_i') { should be <= 604800 }
    its('stdout') { should match /\d+/ }
  end
end

control "STIG_ID_OL6-00-000348_SEV_CAT-2_VULD-ID_V-50641_ftp_banner_benchmark" do
  title "The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner."
  desc  "This setting will cause the system greeting banner to be used for FTP connections as well."
  impact 0.6

  only_if do
    file('/etc/vsftpd/vsftpd.conf').exist?
  end

  describe command('grep "banner_file" /etc/vsftpd/vsftpd.conf ') do
    its('stdout') { should match /banner_file=\/etc\/issue/i }
  end
end

control "STIG_ID_OL6-00-000347_SEV_CAT-2_VULD-ID_V-50643_netrc_files_benchmark" do
  title "There must be no .netrc files on the system."
  desc  "Unencrypted passwords for remote FTP servers may be stored in .netrc files. DoD policy requires passwords be encrypted in storage and not used in access scripts."
  impact 0.6  

  describe command('find /root /home -xdev -name .netrc') do
    its('stdout') { should_not match /^.+/ }
  end
end

control "STIG_ID_OL6-00-000089_SEV_CAT-2_VULD-ID_V-50647_disable_source_routed_packets_benchmark" do
  title "The system must not accept IPv4 source-routed packets by default"
  desc  "Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required."
  impact 0.6

  describe command('sysctl net.ipv4.conf.default.accept_source_route') do
    its('stdout') { should match /^net.ipv4.conf.default.accept_source_route\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000090_SEV_CAT-2_VULD-ID_V-50651_disable_ICMP4_routed_packets_benchmark" do
  title "The system must not accept ICMPv4 secure redirect packets by default."
  desc  "Accepting secure ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required."
  impact 0.6

  describe command('sysctl net.ipv4.conf.default.secure_redirects') do
    its('stdout') { should match /^net.ipv4.conf.default.secure_redirects\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000091_SEV_CAT-3_VULD-ID_V-50655_disable_ICMP4_routed_messages_benchmark" do
  title "The system must ignore ICMPv4 redirect messages by default."
  desc  "This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required."
  impact 0.3

  describe command('sysctl net.ipv4.conf.default.accept_redirects') do
    its('stdout') { should match /^net.ipv4.conf.default.accept_redirects\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000092_SEV_CAT-3_VULD-ID_V-50657_disable_ICMP4_broadcast_address_benchmark" do
  title "The system must not respond to ICMPv4 sent to a broadcast address."
  desc  "Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network."
  impact 0.3

  describe command('sysctl net.ipv4.icmp_echo_ignore_broadcasts') do
    its('stdout') { should match /^net.ipv4.icmp_echo_ignore_broadcasts\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000004_SEV_CAT-3_VULD-ID_V-50661_/var/log/audit_mounted_on_own_parition _benchmark" do
  title "The system must use a separate file system for the system audit data path."
  desc  "Placing /var/log/audit in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space."
  impact 0.3

  describe command('mount | grep "on /var/log/audit "') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000093_SEV_CAT-3_VULD-ID_V-50663_disable_ICMP4_broadcast_address_benchmark" do
  title "The system must ignore ICMPv4 bogus error responses."
  desc  "Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged."
  impact 0.3

  describe command('sysctl net.ipv4.icmp_ignore_bogus_error_responses') do
    its('stdout') { should match /^net.ipv4.icmp_ignore_bogus_error_responses\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000346_SEV_CAT-3_VULD-ID_V-50665_daemon_umask_benchmark" do
  title "The system default umask for daemons must be 027 or 022."
  desc  "The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions."
  impact 0.3

  describe command('grep umask /etc/init.d/functions') do
    its('stdout') { should match /(022|027)/ }
  end
end

control "STIG_ID_OL6-00-000345_SEV_CAT-3_VULD-ID_V-50667_login.defs_umask_benchmark" do
  title "The system default umask in /etc/login.defs must be 077."
  desc  "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  impact 0.3

  describe command('grep -i "umask" /etc/login.defs') do
    its('stdout') { should match /077/ }
  end
end

control "STIG_ID_OL6-00-000344_SEV_CAT-3_VULD-ID_V-50669_profile_umask_benchmark" do
  title "The system default umask in /etc/profile must be 077."
  desc  "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  impact 0.3

  describe command('grep "umask" /etc/profile') do
    its('stdout') { should match /077/ }
  end
end

control "STIG_ID_OL6-00-000005_SEV_CAT-2_VULD-ID_V-50671_space_left_action_benchmark" do
  title "The audit system must alert designated staff members when the audit storage volume approaches capacity."
  desc  "Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption."
  impact 0.6

  describe command('grep ^space_left_action /etc/audit/auditd.conf') do
    its('stdout') { should match /(EMAIL|SYSLOG)/i }
  end
end

control "STIG_ID_OL6-00-000343_SEV_CAT-3_VULD-ID_V-50673_csh_shell_umask_benchmark" do
  title "The system default umask for the csh shell must be 077."
  desc  "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  impact 0.3

  describe command('grep "umask" /etc/csh.cshrc') do
    its('stdout') { should match /077/ }
  end
end

control "STIG_ID_OL6-00-000007_SEV_CAT-3_VULD-ID_V-50677_/home_mounted_on_own_parition_benchmark" do
  title "The system must use a separate file system for user home directories."
  desc  "Ensuring that /home is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage."
  impact 0.3

  describe command('mount | grep "on /home "') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000095_SEV_CAT-2_VULD-ID_V-50683_use_syncookies_benchmark" do
  title "The system must be configured to use TCP syncookies when experiencing a TCP SYN flood."
  desc  "A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests."
  impact 0.6

  describe command('sysctl net.ipv4.tcp_syncookies') do
    its('stdout') { should match /^net.ipv4.tcp_syncookies\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000096_SEV_CAT-2_VULD-ID_V-50685_reverse_path_filter_benchmark" do
  title "The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces."
  desc  "Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks."
  impact 0.6

  describe command('sysctl net.ipv4.conf.all.rp_filter') do
    its('stdout') { should match /^net.ipv4.conf.all.rp_filter\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000008_SEV_CAT-1_VULD-ID_V-50689_gpgpubkey_install_benchmark" do
  title "Vendor-provided cryptographic certificates must be installed to verify the integrity of system software."
  desc  "This key is necessary to cryptographically verify packages that packages are from the operating system vendor"
  impact 1.0

  describe command('rpm -q gpg-pubkey') do
    its('exit_status') { should eq 0 }
  end
end

control "STIG_ID_OL6-00-000009_SEV_CAT-3_VULD-ID_V-50693_rhnsd_disabled_benchmark" do
  title "The Red Hat Network Service (rhnsd) service must not be running, unless it is being used to query the Oracle Unbreakable Linux Network for updates and information."
  desc  "Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system needs to communicate with the Oracle Unbreakable Linux Network for updates or information, then the rhnsd daemon can remain on."
  impact 0.3

  only_if do
    file('/etc/init.d/rhnsd').exist?
  end

  describe service('rhnsd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000097_SEV_CAT-2_VULD-ID_V-50699_reverse_path_IPv4_benchmark" do
  title "The system must use a reverse-path filter for IPv4 network traffic when possible by default."
  desc  "Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks."
  impact 0.6

  describe command('sysctl net.ipv4.conf.default.rp_filter') do
    its('stdout') { should match /^net.ipv4.conf.default.rp_filter\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000013_SEV_CAT-2_VULD-ID_V-50701_gpgcheck_enabled_benchmark" do
  title "The system package management tool must cryptographically verify the authenticity of system software packages during installation."
  desc  "Ensuring the validity of packages' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering."
  impact 0.6

  describe command('grep gpgcheck /etc/yum.conf') do
    its('stdout') { should match /^gpgcheck=1/ }
  end
end

control "STIG_ID_OL6-00-000098_SEV_CAT-2_VULD-ID_V-50705_IPv6_disabled_benchmark" do
  title "The IPv6 protocol handler must not be bound to the network stack unless needed."
  desc  "Any unnecessary network stacks - including IPv6 - should be disabled, to reduce the vulnerability to exploitation."
  impact 0.6

  describe command('grep -r ipv6 /etc/modprobe.d') do
    its('stdout') { should match /^net.ipv6.conf.all.disable_ipv6\s+=\s+1/ }
  end
end

control "STIG_ID_OL6-00-000342_SEV_CAT-3_VULD-ID_V-50707_bashrc_umask_benchmark" do
  title "The system default umask for the bash shell must be 077."
  desc  "The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users."
  impact 0.3

  describe command('grep "umask" /etc/bashrc') do
    its('stdout') { should match /077/ }
  end
end

control "STIG_ID_OL6-00-000015_SEV_CAT-3_VULD-ID_V-50709_gpgcheck_benchmark" do
  title "The system package management tool must cryptographically verify the authenticity of all software packages during installation."
  desc  "Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering."
  impact 0.3

  describe command('grep -ir gpgcheck /etc/yum.repos.d/') do
    its('stdout') { should_not match /gpgcheck=0/ }
  end
end

control "STIG_ID_OL6-00-000099_SEV_CAT-2_VULD-ID_V-50711_ICMPv6_redirect_benchmark" do
  title "The system must ignore ICMPv6 redirects by default."
  desc  "An illicit ICMP redirect message could result in a man-in-the-middle attack."
  impact 0.6

  describe command('sysctl net.ipv6.conf.default.accept_redirects') do
    its('stdout') { should match /^net.ipv6.conf.default.accept_redirects\s+=\s+0/ }
  end
end

control "STIG_ID_OL6-00-000341_SEV_CAT-1_VULD-ID_V-50713_snmp_password_benchmark" do
  title "The snmpd service must not use a default password."
  desc  "Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system."
  impact 1.0

  only_if do
    file('/etc/snmp/snmpd.conf').exist?
  end

  describe command('grep -v "^#" /etc/snmp/snmpd.conf| grep public') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000016_SEV_CAT-2_VULD-ID_V-50715_aide_installed_benchmark" do
  title "A file integrity tool must be installed."
  desc  "The AIDE package must be installed if it is to be available for integrity checking."
  impact 0.6

  describe package('aide') do
    it { should be_installed }
  end
end

control "STIG_ID_OL6-00-000340_SEV_CAT-2_VULD-ID_V-50717_snmpv3_benchmark" do
  title "The snmpd service must use only SNMP protocol version 3 or newer."
  desc  "Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information."
  impact 0.6

  only_if do
    file('/etc/snmp/snmpd.conf').exist?
  end

  describe command('grep -v "^#" /etc/snmp/snmpd.conf| grep public') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000019_SEV_CAT-1_VULD-ID_V-50719_no_rhosts/hosts.equiv_benchmark" do
  title "There must be no .rhosts or hosts.equiv files on the system."
  desc  "Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system."
  impact 1.0

  describe file('/etc/hosts.equiv') do
    it { should_not exist }
  end

  describe command('ll -a /home/*/ |grep .rhosts') do
    its('stdout') { should_not match /.+/ }
  end

  describe command('ll -a /root/ |grep .rhosts') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000027_SEV_CAT-2_VULD-ID_V-50721_root_over_virtual-console_benchmark" do
  title "The system must prevent the root account from logging in from virtual consoles."
  desc  "Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account."
  impact 0.6

  describe command('grep \'^vc/[0-9]\' /etc/securetty') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000028_SEV_CAT-3_VULD-ID_V-50725_root_over_serial_benchmark" do
  title "The system must prevent the root account from logging in from serial consoles."
  desc  "Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account."
  impact 0.3

  describe command('grep \'^ttyS[0-9]\' /etc/securetty') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000029_SEV_CAT-2_VULD-ID_V-50731_OS_accounts_locked_benchmark" do
  title "Default operating system accounts, other than root, must be locked."
  desc  "Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system."
  impact 0.6

  command('awk -F: \'$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1}\' /etc/shadow').stdout.split.each do |user_name|
    describe user(user_name) do
      its('uid') { should be >= 500 }
    end
  end
end

control "STIG_ID_OL6-00-000030_SEV_CAT-1_VULD-ID_V-50737_use_null_passwords_benchmark" do
  title "The system must not have accounts configured with blank or null passwords."
  desc  "If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments."
  impact 1.0

  describe command('grep nullok /etc/pam.d/system-auth') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000339_SEV_CAT-3_VULD-ID_V-50739_FTP_logging_benchmark" do
  title "The FTP daemon must be configured for logging or verbose mode"
  desc  "To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log."
  impact 0.3

  only_if do
    file('/etc/init.d/vsftpd').exist?
  end

  if File.directory?('/etc/xinetd.d')
    conf_file = command('grep vsftpd /etc/xinetd.d/* | grep server_args | awk -F= \'{print $2}\'').stdout
  else
    conf_file = '/etc/vsftpd/vsftpd.conf'
  end
  describe command("grep -i xferlog_enable #{conf_file}") do
    its('stdout') { should match /xferlog_enable=YES/i }
  end
end

control "STIG_ID_OL6-00-000031_SEV_CAT-2_VULD-ID_V-50741_no_password_hashes_in_/etc/passwd_benchmark" do
  title "The /etc/passwd file must not contain password hashes."
  desc  "The hashes for all user account passwords should be stored in the file /etc/shadow and never in /etc/passwd, which is readable by all users."
  impact 0.6

  describe command('awk -F: \'($2 != "x") {print}\' /etc/passwd ') do
    its('stdout') { should_not match /.+/ }
  end
end

control "STIG_ID_OL6-00-000032_SEV_CAT-2_VULD-ID_V-50747_only_root_is_0_/etc/passwd_benchmark" do
  title "The root account must be the only account having a UID of 0."
  desc  "An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner."
  impact 0.6

  describe passwd.uid(0) do
    its('users') { should cmp 'root' }
    its('count') { should eq 1 }
  end
end

control "STIG_ID_OL6-00-000338_SEV_CAT-1_VULD-ID_V-50751_tftp_-s_/etc/passwd_benchmark" do
  title "The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system."
  desc  "Using the -s option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private."
  impact 1.0

  only_if do
    file('/etc/xinetd.d/tftp').exist?
  end

  describe command('grep "server_args" /etc/xinetd.d/tftp') do
    its('stdout') { should match /-s/i }
  end
end

control "STIG_ID_OL6-00-000033_SEV_CAT-2_VULD-ID_V-50753_/etc/shadow_owner_benchmark" do
  title "The /etc/shadow file must be owned by root"
  desc  "The /etc/shadow file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture."
  impact 0.6

  describe file('/etc/shadow') do
    its('owner') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000034_SEV_CAT-2_VULD-ID_V-50755_/etc/shadow_group_owner_benchmark" do
  title "The /etc/shadow file must be group-owned by root."
  desc  "The /etc/shadow file stores password hashes. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/shadow') do
    its('group') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000035_SEV_CAT-2_VULD-ID_V-50757_/etc/shadow_mode_benchmark" do
  title "The /etc/shadow file must have mode 0000."
  desc  "The /etc/shadow file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture."
  impact 0.6

  describe file('/etc/shadow') do
    its('mode') { should eq 0000 }
  end
end

control "STIG_ID_OL6-00-000036_SEV_CAT-2_VULD-ID_V-50759_/etc/gshadow_owner_benchmark" do
  title "The /etc/gshadow file must be owned by root."
  desc  "The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/gshadow') do
    its('owner') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000103_SEV_CAT-2_VULD-ID_V-50761_IPV6_firewall_benchmark" do
  title "The system must employ a local IPv6 firewall."
  desc  "The ip6tables service provides the system's host-based firewalling capability for IPv6 and ICMPv6."
  impact 0.6

  only_if do
    command('sysctl -a|grep net.ipv6.conf.all.disable_ipv6 |awk -F= \'{print $2}\'').stdout.to_i == 1
  end
  describe service('ip6tables') do
    it { should be_running }
  end
end

control "STIG_ID_OL6-00-000037_SEV_CAT-2_VULD-ID_V-50763_/etc/gshadow_group_owner_benchmark" do
  title "The /etc/gshadow file must be group-owned by root."
  desc  "The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/gshadow') do
    its('group') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000038_SEV_CAT-2_VULD-ID_V-50765_/etc/gshadow_mode_benchmark" do
  title "The /etc/gshadow file must have mode 0000."
  desc  "The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/gshadow') do
    its('mode') { should eq 0000 }
  end
end

control "STIG_ID_OL6-00-000106_SEV_CAT-2_VULD-ID_V-50767_IPV6_firewall_benchmark" do
  title "The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture."
  desc  "The  ip6tables service provides the system's host-based firewalling capability for IPv6 and ICMPv6."
  impact 0.6

  only_if do
    command('sysctl -a|grep net.ipv6.conf.all.disable_ipv6 |awk -F= \'{print $2}\'').stdout.to_i == 1
  end
  describe service('ip6tables') do
    it { should be_running }
  end
end

control "STIG_ID_OL6-00-000039_SEV_CAT-2_VULD-ID_V-50769_/etc/passwd_owner_benchmark" do
  title "The /etc/passwd file must be owned by root."
  desc  "The /etc/passwd file contains information about the users that are configured on the system. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/passwd') do
    its('owner') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000040_SEV_CAT-2_VULD-ID_V-50771_/etc/passwd_group_owner_benchmark" do
  title "The /etc/passwd file must be group-owned by root."
  desc  "The /etc/passwd file contains information about the users that are configured on the system. Protection of this file is critical for system security."
  impact 0.6

  describe file('/etc/passwd') do
    its('group') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000041_SEV_CAT-2_VULD-ID_V-50773_/etc/passwd_mode_benchmark" do
  title "The /etc/passwd file must have mode 0644 or less permissive."
  desc  "If the /etc/passwd file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security."
  impact 0.6

  describe command('stat -c %a /etc/passwd') do
    its('stdout.to_i') { should be <= 644 }
  end
end

control "STIG_ID_OL6-00-000042_SEV_CAT-2_VULD-ID_V-50775_/etc/group_owner_benchmark" do
  title "The /etc/group file must be owned by root."
  desc  "The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security."
  impact 0.6

  describe file('/etc/group') do
    its('owner') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000043_SEV_CAT-2_VULD-ID_V-50777_/etc/group_group_owner_benchmark" do
  title "The /etc/group file must be group-owned by root."
  desc  "The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security."
  impact 0.6

  describe file('/etc/group') do
    its('group') { should eq 'root' }
  end
end

control "STIG_ID_OL6-00-000044_SEV_CAT-2_VULD-ID_V-50779_/etc/group_mode_benchmark" do
  title "The /etc/group file must have mode 0644 or less permissive."
  desc  "The /etc/group file contains information regarding groups that are configured on the system. Protection of this file is important for system security."
  impact 0.6

  describe command('stat -c %a /etc/group') do
    its('stdout.to_i') { should be <= 644 }
  end
end

control "STIG_ID_OL6-00-000107_SEV_CAT-2_VULD-ID_V-50781_IPV6_firewall_benchmark" do
  title "The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices."
  desc  "The ip6tables service provides the system's host-based firewalling capability for IPv6 and ICMPv6."
  impact 0.6

  only_if do
    command('sysctl -a|grep net.ipv6.conf.all.disable_ipv6 |awk -F= \'{print $2}\'').stdout.to_i == 1
  end

  describe service('ip6tables') do
    it { should be_running }
  end
end

control "STIG_ID_OL6-00-000045_SEV_CAT-2_VULD-ID_V-50783_lib_files_perms_benchmark" do
  title "Library files must have mode 0755 or less permissive."
  desc  "Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system."
  impact 0.6

  dirs = ['/lib', '/lib64', '/usr/lib', '/usr/lib64']
  dirs.each do |dir|
    describe command("find -L #{dir} -perm /022 -type f") do
      its('stdout') { should_not match /.+/ }
    end
  end
end

control "STIG_ID_OL6-00-000046_SEV_CAT-2_VULD-ID_V-50785_lib_files_owned_benchmark" do
  title "Library files must be owned by a system account."
  desc  "Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system."
  impact 0.6

  dirs = ['/lib', '/lib64', '/usr/lib', '/usr/lib64', '/usr/local/lib', '/usr/local/lib64']
  dirs.each do |dir|
    describe command("find -L #{dir} \\! -user root") do
      its('stdout') { should_not match /.+/ }
    end
    describe command("rpm -V -f #{dir} | grep '^.....U'") do
      its('stdout') { should_not match /.+/ }
    end
  end
end

control "STIG_ID_OL6-00-000047_SEV_CAT-2_VULD-ID_V-50787_system_files_perms_benchmark" do
  title "All system command files must have mode 755 or less permissive."
  desc  "System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted."
  impact 0.6

  dirs = ['/bin', '/usr/bin', '/usr/local/bin', '/sbin', '/usr/sbin', '/usr/local/sbin']
  dirs.each do |dir|
    describe command("find -L #{dir} -perm /022 -type f") do
      its('stdout') { should_not match /.+/ }
    end
  end
end

control "STIG_ID_OL6-00-000048_SEV_CAT-2_VULD-ID_V-50789_system_files_owned_benchmark" do
  title "All system command files must be owned by root."
  desc  "System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted."
  impact 0.6

  dirs = ['/bin', '/usr/bin', '/usr/local/bin', '/sbin', '/usr/sbin', '/usr/local/sbin']
  dirs.each do |dir|
    describe command("find -L #{dir} \\! -user root ") do
      its('stdout') { should_not match /.+/ }
    end
  end
end

control "STIG_ID_OL6-00-000050_SEV_CAT-2_VULD-ID_V-50791_password_min_length_benchmark" do
  title "The system must require passwords to contain a minimum of 15 characters."
  desc  "Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result."
  impact 0.6

  describe command('grep PASS_MIN_LEN /etc/login.defs ') do
    its('stdout') { should match /^PASS_MIN_LEN\s+15/ }
  end
end

control "STIG_ID_OL6-00-000051_SEV_CAT-2_VULD-ID_V-50793_password_change_min_benchmark" do
  title "Users must not be able to change passwords more than once every 24 hours."
  desc  "Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement."
  impact 0.6

  describe command('grep PASS_MIN_DAYS /etc/login.defs') do
    its('stdout') { should match /^PASS_MIN_DAYS\s+1/ }
  end
end

control "STIG_ID_OL6-00-000053_SEV_CAT-2_VULD-ID_V-50795_password_change_max_benchmark" do
  title "User passwords must be changed at least every 60 days."
  desc  "Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise."
  impact 0.6

  describe command('grep PASS_MAX_DAYS /etc/login.defs') do
    its('stdout') { should match /^PASS_MAX_DAYS\s+60/ }
  end
end

control "STIG_ID_OL6-00-000113_SEV_CAT-2_VULD-ID_V-50797_IPV4_firewall_benchmark" do
  title "The system must employ a local IPv4 firewall."
  desc  "The iptables service provides the system's host-based firewalling capability for IPv4 and ICMP."
  impact 0.6

  only_if do
    csd == false
  end

  describe service('iptables') do
    it { should be_running }
  end
end

control "STIG_ID_OL6-00-000237_SEV_CAT-2_VULD-ID_V-50799_permit_root_login_benchmark" do
  title "The system must not permit root logins using remote access programs such as ssh."
  desc  "Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password."
  impact 0.6

  describe command('grep -i PermitRootLogin /etc/ssh/sshd_config') do
    its('stdout') { should match /^PermitRootLogin\s+no/i }
  end
end

control "STIG_ID_OL6-00-000239_SEV_CAT-2_VULD-ID_V-50801_allow_blank_passwords_benchmark" do
  title "The SSH daemon must not allow authentication using an empty password."
  desc  "Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere."
  impact 0.6

  describe command('grep -i PermitEmptyPasswords /etc/ssh/sshd_config') do
    its('stdout') { should match /^PermitEmptyPasswords\s+no/i }
  end
end

control "STIG_ID_OL6-00-000240_SEV_CAT-2_VULD-ID_V-50803_sshd_banner_benchmark" do
  title "The SSH daemon must be configured with the Department of Defense (DoD) login banner."
  desc  "The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution."
  impact 0.6

  describe command('grep -i Banner /etc/ssh/sshd_config') do
    its('stdout') { should match /\/etc\/issue/ }
  end
end

control "STIG_ID_OL6-00-000241_SEV_CAT-3_VULD-ID_V-50805_sshd_permit_user_env_benchmark" do
  title "The SSH daemon must not permit user environment settings."
  desc  "SSH environment options potentially allow users to bypass access restriction in some configurations."
  impact 0.3

  describe command('grep PermitUserEnvironment /etc/ssh/sshd_config') do
    its('stdout') { should match /^PermitUserEnvironment\s+no/ }
  end
end

control "STIG_ID_OL6-00-000243_SEV_CAT-2_VULD-ID_V-50807_sshd_ciphers_benchmark" do
  title "The SSH daemon must be configured to use only FIPS 140-2 approved ciphers."
  desc  "Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance."
  impact 0.6

  describe command('grep Ciphers /etc/ssh/sshd_config') do
    its('stdout') { should match /(AES|3DES)/i }
  end
end

control "STIG_ID_OL6-00-000246_SEV_CAT-3_VULD-ID_V-50809_chkconfig_avahi-daemon_benchmark" do
  title "The avahi service must be disabled."
  desc  "Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted."
  impact 0.3

  only_if do
    file('/etc/init.d/avahi-daemon').exist?
  end

  describe service('avahi-daemon') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end

control "STIG_ID_OL6-00-000248_SEV_CAT-2_VULD-ID_V-50813_ntp_servers_benchmark" do
  title "The system clock must be synchronized to an authoritative DoD time source."
  desc  "Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended."
  impact 0.6

  describe command('grep server /etc/ntp.conf') do
    its('stdout') { should match /^server\s+[a-zA-Z0-9].+/i }
  end
end

control "STIG_ID_OL6-00-000249_SEV_CAT-2_VULD-ID_V-50815_local_postfix_benchmark" do
  title "Mail relaying must be restricted."
  desc  "This ensures postfix accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack."
  impact 0.6

  describe command('grep inet_interfaces /etc/postfix/main.cf') do
    its('stdout') { should match /^inet_interfaces\s+=\s+localhost$/i }
  end
end

control "STIG_ID_OL6-00-000252_SEV_CAT-2_VULD-ID_V-50817_ldap_tls_benchmark" do
  title "If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms."
  desc  "The ssl directive specifies whether to use ssl or not. If not specified it will default to no. It should be set to start_tls rather than doing LDAP over SSL."
  impact 0.6

  only_if do
    file('/etc/pam_ldap.conf').exist?
  end

  describe command('grep start_tls /etc/pam_ldap.conf') do
    its('stdout') { should match /^ssl start_tls/i }
  end
end

