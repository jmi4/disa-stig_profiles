# encoding: utf-8
# copyright: 2015, The Authors
# license: All rights reserved
#
# Notes
# There are some stigs that require an administrator interview such as:
# OL6-00-000524/V-50519, OL6-00-000505/V-50613, OL6-00-000504/V-50615
#
# I will have these commented out below, can they are configured to dectect results based on common enterprise setups.


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

  describe command('a=$(sudo grep "^log_file" /etc/audit/auditd.conf|sudo sed "s/^[^/]*//; s/[^/]*$//"|sudo xargs stat -c %a) && if [ $a -lt 756 ]; then echo "pass"; else echo "fail"; fi') do
    its('stdout') { should match /pass/i }
  end
end
