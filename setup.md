  - [sudo](#sudo)
  - [host](#host)
  - [SSH](#ssh)
  - [Firewall](#firewall)
  - [Fail2Ban](#fail2ban)
  - [Tripwire](#tripwire)
  - [Maldet](#maldet)
  - [RKHunter](#rkhunter)
  - [Automatic Security Updates](#automatic-security-updates)
  - [Accurate UTC Time](#accurate-utc-time)
  - [Server Monitor](#server-monitor)
  - [Nginx](#nginx)
  - [Node](#node)
  - [Additional](#additional)

## sudo

Most the commands below should be ran with `sudo` or as `root`. I've omitted them to simplify the examples.

## host

##### Change host name to domain

``` bash
hostname [DOMAIN].[TLD]
```

You can verify the hostname user `hostname -f`.

##### Add new host name to host file
``` bash
nano /etc/hosts
```

Change the entries so that they look something like
``` bash
127.0.0.1 localhost
127.0.0.1 [DOMAIN].[TLD] [DOMAIN].[TLD]
```

##### Add host name to mail local hosts
``` bash
nano /etc/mail/local-host-names
```

Change the entries so that they look something like
``` bash
localhost
[DOMAIN].[TLD]
```



## SSH

##### Add new user. [Enter strong pw and answer prompts]
``` bash
adduser [USER_NAME]
```

##### Add user to sudo group [Run as root]
``` bash
gpasswd -a [USER_NAME] sudo
```

##### Switch to the new user
``` bash
su - [USER_NAME]
```

##### Make the .ssh dir
``` bash
mkdir .ssh
```
``` bash
chmod 700 .ssh
```

##### Make key file and enter pub key
``` bash
nano .ssh/authorized_keys
```

##### Change permissions
``` bash
chmod 600 .ssh/authorized_keys
```

##### Exit to root
``` bash
exit
```

##### Config SSH Daemon

``` bash
nano /etc/ssh/sshd_config
```

##### Add/change the follow
  * `RSAAuthentication yes`
  * `PubkeyAuthentication yes`

##### Disable root login [Add/change the following]
  * `PermitRootLogin no`

##### Disable password login [Add/change the following]
  * `ChallengeResponseAuthentication no`
  * `PasswordAuthentication no`
  * `UsePAM no`

##### Explicitly allow users [Add the following]
  * ```AllowUsers [USER_NAME]```

You can also allow groups by adding `AllowGroups [GROUP_NAME]` or you can allow a user from a specific IP address using `AllowUsers [USER_NAME]@[IP_ADDRESS]`

##### Save file and restart SSH
``` bash
service ssh restart
```



## Firewall

##### Check for UFW service
``` bash
service --status-all | grep "ufw"
```

##### Add SSH connections
``` bash
ufw allow ssh
```
Same as `ufw allow 22/tcp`. If changed ssh port use `ufw allow [SSH_PORT]/tcp`

##### Add HTTP web traffic
```bash
ufw allow www
```
Same as `ufw allow 80/tcp`

##### HTTPS web traffic
ufw allow 443/tcp

##### Limit connection attempts on ssh.
``` bash
ufw limit 22/tcp
```
If changed ssh port use `ufw limit [SSH_PORT]/tcp`

##### Deny everything that hasn't been whitelisted
``` bash
ufw default deny
```

##### Activate rules
``` bash
ufw enable
```

Other useful commands
  * `ufw allow ftp` or `ufw allow 21/tcp` for FTP connections
  * `ufw show added` can used to check added rules
  * `ufw status` can be used to check active rules
  * `ufw disable` to turn off firewall
  * `nano /etc/default/ufw` and change `IPV6=yes` if you need IP v6 support
  * `ufw status numbered` to get a numbered list and then `ufw delete [NUMBER]` to delete a rule. `ufw delete [RULE]` i.e `ufw delete allow ssh` can also be used
  * `ufw reset` to reset all rules



## Fail2Ban

##### Install
``` bash
apt-get install fail2ban
```

##### Make a local copy of config
``` bash
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

##### Open config
``` bash
nano /etc/fail2ban/jail.local
```

##### Add personal IPs to whitelisted [space seperated]
``` bash
ignoreip = 127.0.0.1/8 [IP_ADDRESS]
```

##### Change ban time if desired
``` bash
bantime  = 600
```
The default time is 10 minutes (600 seconds).

##### Change find time if desired
``` bash
findtime  = 600
```
The default time is 10 minutes (600 seconds).

##### Change max tries if desired
``` bash
maxretry = 5
```

A host is banned if it has generated `maxretry` during the last `findtime` seconds.

##### Set warn email if mail server available
``` bash
destemail = [EMAIL_ADDRESS]
```
If you need/want emails you may need to install sendmail `apt-get install sendmail`.

##### Change Actions
``` bash
action = %(action_)s
```
Options
  * `action_` - bans user.
  * `action_mw` - bans user & sends WhoIs report.
  * `action_mwl` - bans user, sends WhoIs report & all relevant lines from log file.


##### Config Jails
In the `### JAILS ###` section you can configure each application separately, these overwrite the defaults from earlier in the config. Each jail can have the following options:
  * `enabled` - Whether or not the filter is on (SSH is on by default).
  * `port` - The port the service is running on.
  * `filter` - Name of the failregex to use. Found in `/etc/fail2ban/filter.d`.
  * `logpath` - The service's log path.
  * `maxretry` - [Same as above].
  * `findtime` - [Same as above].
  * `bantime` - [Same as above].
  * `action` - The action to use.

Jails of note are the `[nginx-http-auth]` and `[nginx-botsearch]` which you will probably need to add/uncomment the enabled flag.

##### Additional Jails
May also want to add the `[nginx-noscript]` (If you do not use PHP, Perl, etc), `[nginx-badbots]`,  and `[nginx-noproxy]` jails. These should be added to the aforementioned `/etc/fail2ban/jail.local`
```
[nginx-noscript]

enabled  = true
port     = http,https
filter   = nginx-noscript
logpath  = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]

enabled  = true
port     = http,https
filter   = nginx-badbots
logpath  = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]

enabled  = true
port     = http,https
filter   = nginx-noproxy
logpath  = /var/log/nginx/access.log
maxretry = 2
```

##### Fail Regexes
``` bash
nano /etc/fail2ban/filter.d/nginx-http-auth.conf
```
Under the predefined regex add an additional one.

```
failregex = ^ \[error\] \d+#\d+: \*\d+ user "\S+":? (password mismatch|was not found in ".*"), client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"\s*$
            ^ \[error\] \d+#\d+: \*\d+ no user/password was provided for basic authentication, client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"\s*$
```
Copy the existing `apache-badbots.conf`. This regex can be used as is, copy for clarity.
``` bash
cp /etc/fail2ban/filter.d/apache-badbots.conf /etc/fail2ban/filter.d/nginx-badbots.conf
```

Create+Open the nginx-noscript regex.
``` bash
nano /etc/fail2ban/filter.d/nginx-noscript.conf
```
Add
```
[Definition]

failregex = ^<HOST> -.*GET.*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scgi)

ignoreregex =
```

Create+Open the nginx-noproxy regex.
``` bash
nano /etc/fail2ban/filter.d/nginx-noproxy.conf
```
Add
```
[Definition]

failregex = ^<HOST> -.*GET http.*

ignoreregex =
```

##### Restart fail2ban
``` bash
service fail2ban restart
```

##### Additional
If you set up the host and the fail2ban config to email on bans, the following commands can be used to completely block an offender.
  * `iptables -A INPUT -s [OFFENDING_IP] -j DROP`
  * `iptables -A OUTPUT -d [OFFENDING_IP] -j DROP`

The `-A` appends this rule to the given table [INPUT,OUTPUT], the `-s` means `source` and the `-d` means `destination`. `-j` means `jump`, which is basically saying 'do the following', in this case, `DROP` the packet. So these rules say 'drop all incoming packets __from__ this IP' and 'drop all outgoing packets __to__ this IP'.

There's also a script in the `/scripts/block` directory in case you need to block a large list of IPs and don't want to type each one out by hand.


Other useful commands
  * `fail2ban-client status` to get a list of enabled jails
  * `fail2ban-client status [JAIL_NAME]` to get more specific information
  * `fail2ban-client set nginx-http-auth unbanip [IP_ADDRESS]` to unban an ip address
  * `iptables -S` to see the iptable rules created



## Tripwire

##### Install the packages
``` bash
apt-get install tripwire
```

During the installation it will ask you if you want to use a passphrase and if it can rebuild a few files. Answer `yes` to all. It will then ask you for a site passphrase, this phrase is used to encrypt the configuration files that it uses so they can not be tampered with. Following that it will ask for a local passphrase, this is used to run the binaries.

##### Initialize database
``` bash
# Will prompt for SITE passphrase
twadmin --create-polfile /etc/tripwire/twpol.txt

# Will prompt for LOCAL passphrase
# It will complain about a lot of things since the policy is generic.
tripwire --init
```

##### Get initial results
``` bash
# This runs the scan and only prints out the found files.
tripwire --check | grep Filename
```
Copy these files somewhere so we can use them in the config

##### Open policy file
``` bash
nano /etc/tripwire/twpol.txt
```

In the boot section you can comment out `/etc/rc.boot` if you are on Ubuntu. Now using the previous list, find the items in the policy file and comment the out. Most will be in the `/root/` section. The rest will likely be `/proc/*` which change all the time.

##### Configure /proc checks
In the `Devices & Kernel information` section comment out `/proc -> $(Device) ;` this directive says to scan all of `/proc`. Now add the `/proc` locations we do want.
```
{
    /dev                    -> $(Device) ;
    #/proc                  -> $(Device) ;
    /proc/devices           -> $(Device) ;
    /proc/net               -> $(Device) ;
    /proc/tty               -> $(Device) ;
    /proc/sys               -> $(Device) ;
    /proc/cpuinfo           -> $(Device) ;
    /proc/modules           -> $(Device) ;
    /proc/mounts            -> $(Device) ;
    /proc/dma               -> $(Device) ;
    /proc/filesystems       -> $(Device) ;
    /proc/interrupts        -> $(Device) ;
    /proc/ioports           -> $(Device) ;
    /proc/scsi              -> $(Device) ;
    /proc/kcore             -> $(Device) ;
    /proc/self              -> $(Device) ;
    /proc/kmsg              -> $(Device) ;
    /proc/stat              -> $(Device) ;
    /proc/loadavg           -> $(Device) ;
    /proc/uptime            -> $(Device) ;
    /proc/locks             -> $(Device) ;
    /proc/meminfo           -> $(Device) ;
    /proc/misc              -> $(Device) ;
}
```
Also add `/dev/pts` to this section.
```
/dev/pts                -> $(Device) ;
```

##### System service changes
In the `System boot changes` section comment out `/var/lock -> $(SEC_CONFIG) ;` and `/var/run -> $(SEC_CONFIG) ;` so that we don't get false positives from normal services changing files.

##### Recreate policy
``` bash
# Will prompt for SITE passphrase
twadmin -m P /etc/tripwire/twpol.txt
```

##### Reinitialize database
``` bash
# Will prompt for LOCAL passphrase
tripwire --init
```
You should not get any warnings at this point.

##### Run a check
``` bash
tripwire --check
```
This will allow you to double check that all configuration is correct.

##### Clean up
We should remove the plaintext policy file.
``` bash
rm /etc/tripwire/twpol.txt
```

Other useful commands
  * `twadmin --generate-keys --site-keyfile /etc/tripwire/site.key` - Generate a new SITE passphrase.
  * `twadmin --generate-keys --local-keyfile /etc/tripwire/$HOSTNAME-local.key` - Generate a new LOCAL passphrase.
  * `tripwire --init --cfgfile /etc/tripwire/tw.cfg --polfile /etc/tripwire/tw.pol --site-keyfile /etc/tripwire/site.key --local-keyfile /etc/tripwire/$HOSTNAME-local.key` - Generate a new database file.
  * `twadmin --print-polfile > /etc/tripwire/twpol.txt` - To generate an editable plain text policy file.
  * `tripwire --check --interactive` - This runs the check and generates an extremely in-depth text file of the results and opens it with your default text editor. Near the top it will show a list of checkboxes that relate to the files that have changed. You can remove the 'X' [Deny] to keep checking these files. Leaving the 'X' will [Accept] update the file in the database (wont flag on next run). This is the command that you will use when when your notified of a change.



## Maldet
--------------------------------------------------------------

##### Move to src directory
``` bash
cd /usr/local/src/
```

##### Download and extract tar file
``` bash
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar -xzf maldetect-*
```

##### Move to extracted folder
``` bash
cd maldetect-*
```

##### Run installer
``` bash
sh ./install.sh
```

##### Configuration
``` bash
nano /usr/local/maldetect/conf.maldet
```

All options are well commented so there's not much point to go over them all in detail, the important options are:
  * `autoupdate_signatures` - Enables/disables daily definition updates.
  * `autoupdate_version` - Enables/disables daily maldet application updates.
  * `email_alert` - This will enable/disable email alerts.
  * `email_addr` - The email address to send alerts.
  * `quarantine_hits` - What to do when malware is found. Either email only or email and quarantine. The later ("1") is preferred.
  * `quarantine_clean` - Whether to atempt to clean malware. Requires `quarantine_hits` to be "1". Preferred setting is "1", clean.
  * `quarantine_suspend_user` - Whether to suspend user account that has hits.
  * `quarantine_suspend_user_minuid` - The minimum userid value that can be suspended.

##### Update signatures
``` bash
maldet -u
```

Other useful commands:
  * `maldet --scan-all [PATH]` - Scan the files in the provided path.
  * `maldet --scan-recent [PATH] [DAYS]` - Scan only the files that have changed in the provided path in the last X days.
  * `maldet --quarantine [SCANID]` - Quarantines found malware from previous scan.
  * `maldet --clean [SCANID]` - Attempt to clean found malware from previous scan.
  * `maldet --restore [FILE]` - Restore a quarantined file.
  * `maldet -l` - To view the recent logs.

Maldet installs a daily cron job, located @ `/etc/cron.daily/maldet`, that performs app and signature updates, prunes old data and runs a daily scan of recently changed files.



## RKHunter

##### Move to src directory
``` bash
cd /usr/local/src/
```

##### Download and extract tar file
``` bash
wget http://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.2/rkhunter-1.4.2.tar.gz
tar -xzf rkhunter-*
```

##### Move to extracted folder
``` bash
cd rkhunter-*
```

##### Run installer
``` bash
sh ./installer.sh --layout /usr --install
```

##### Update definitions
``` bash
rkhunter --update
```

##### Get baseline files
``` bash
rkhunter --propupd
```

##### Perform initial run (This will produce results, this is expected)
``` bash
# This runs the scan and only prints out the warnings
rkhunter -c --enable all --disable none --rwo
```
Copy these warnings somewhere so we can use them in the config

##### Open config file
``` bash
nano /etc/rkhunter.conf
```

If your sever is new, chances are you can whitelist the few results that were found previously. You can scroll down to the `SCRIPTWHITELIST` section and add the ones you found.
```
SCRIPTWHITELIST="/usr/sbin/adduser"
SCRIPTWHITELIST="/usr/bin/ldd"
```
You may also get some warnings pertaining to hidden files and directories, usually in /dev. You can handle these using the following directives:
  * `ALLOWDEVFILE`
  * `ALLOWHIDDENDIR`
  * `ALLOWHIDDENFILE`

You may also want to configure the following:
  * `MAIL-ON-WARNING` - Whether or not to mail when something is found.
  * `MAIL_CMD` - The command to use when mailing. Default is `mail`.

##### Check the config syntax
``` bash
rkhunter -C
```

##### Update the file properties and run the scan add-error-page-handling
``` bash
rkhunter --propupd
rkhunter -c --enable all --disable none --rwo
```

If everything was white listed you should get a clean scan. Remember, when you make software changes to run `rkhunter --propupd` to update the file properties list.



## Automatic Security Updates

##### Install (If you dont already have it)
``` bash
apt-get install -y unattended-upgrades
```

##### Open and edit config file
``` bash
nano /etc/apt/apt.conf.d/50unattended-upgrades
```

``` bash
# Make sure just security is active
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
//      "${distro_id}:${distro_codename}-updates";
//      "${distro_id}:${distro_codename}-proposed";
//      "${distro_id}:${distro_codename}-backports";
};
```

Some updates require a reboot, alter the following line if you want to allow auto-reboot
``` bash
Unattended-Upgrade::Automatic-Reboot "true";
```

If you do allow auto-reboot you can specify the reboot time
``` bash
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
```

##### Set update email if mail server available

``` bash
Unattended-Upgrade::Mail "[EMAIL_ADDRESS]";
```

##### Open and edit the periodic config
``` bash
# The file name may be something different, format [##]periodic
nano /etc/apt/apt.conf.d/10periodic
```

```
# Make sure these are present. Will check for upgrades once per day.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
```

Upgrade logs can be found in `/var/log/unattended-upgrades/`.



## Accurate UTC Time
--------------------------------------------------------------

##### Open the server timezone config dialog
``` bash
dpkg-reconfigure tzdata
```
   * Select 'None of the above' (or 'Etc' depending on version) from the first menu
   * Select 'UTC' from the second
   * Should get output that looks like..
    ``` bash
    Current default time zone: 'Etc/UTC'
    Local time is now:      Wed Jul 27 16:17:32 UTC 2016.
    Universal Time is now:  Wed Jul 27 16:17:32 UTC 2016.
    ```

##### NTP synchronization
``` bash
apt-get install ntp
```



## Server Monitor
--------------------------------------------------------------

##### Create New Relic account
```
https://newrelic.com/signup
```

##### Add New Relic repository and signing key
``` bash
echo deb http://apt.newrelic.com/debian/ newrelic non-free | tee /etc/apt/sources.list.d/newrelic.list
```

##### Trust key
``` bash
wget -O- https://download.newrelic.com/548C16BF.gpg | apt-key add -
```

##### Install New Relic
``` bash
apt-get install newrelic-sysmond
```

##### Set license key
``` bash
nrsysmond-config --set license_key=[LICENSE_KEY]
```

Your license key can be found

##### Set host name (optional)
``` bash
nano /etc/newrelic/nrsysmond.cfg
```

Scroll down and find `hostname=` and change it to the name you want to show in the New Relic admin panel.

##### Start service
``` bash
service newrelic-sysmond start
```

##### Setup email alerts



## Nginx
--------------------------------------------------------------

``` bash
apt-get install nginx
```

##### Open nginx config
``` bash
nano /etc/nginx/nginx.conf
```

##### Change server_tokens
``` bash
server_tokens off;
```

##### Make a local copy of default server config
``` bash
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/site
```

##### Open server config
``` bash
nano /etc/nginx/sites-available/site
```

##### Add error page handling
``` bash
# In the server {} block
error_page 401 403 404 /404.html;
```

###### Example [Simple Node app]
``` bash
server {
    listen 80;

    server_name [SERVER_HOST_NAME];

    location / {
      proxy_redirect off;
      proxy_pass            http://127.0.0.1:3000;
      proxy_set_header      X-Real-IP $remote_addr;
      proxy_set_header      X-Forwarded-For  $proxy_add_x_forwarded_for;
      proxy_set_header      X-Forwarded-Proto $scheme;
      proxy_set_header      Host $http_host;
      proxy_set_header      X-NginX-Proxy true;
      proxy_set_header      Upgrade $http_upgrade;
      proxy_set_header      Connection 'upgrade';
      proxy_http_version    1.1;
      proxy_cache_key       sfs$request_uri$scheme;
      error_page 401 403 404 /404.html;
   }
}
```

##### Symlink server to enabled
``` bash
ln -s etc/nginx/sites-available/site etc/nginx/sites-enabled/site
```

##### Remove default enabled site
``` bash
rm etc/nginx/sites-enabled/default
```

##### Reload nginx
``` bash
service nginx reload
```

A more thorough config can be found in the _nginx-configs_ directory.



## Node
--------------------------------------------------------------

##### Add Node 4.x LTS PPA
``` bash
curl -sL https://deb.nodesource.com/setup_4.x | bash -
```

##### Install node
``` bash
apt-get install nodejs
```

##### Version
As of writing this, Node is on v6.x. The only current LTS version is v4.x, hence the above install of v4.x. You can check the [LTS Schedule](https://github.com/nodejs/LTS#lts_schedule) to determine if you want/need to change the installed version.


## Additional Utils
If you set the various configurations up to mail you results you'll need to install the following mail packages.
  * `apt-get install sendmail`
  * `apt-get install mailutils`


## Useful management commands
  * `cut -d: -f1 /etc/passwd` - List all users (from `/etc/passwd`). This includes both actual users and system 'users'.
  * `getent passwd` - Same as above but gives a little more information for each user.
  * `ps aux | less` - List running processes.
  * `top` - Realtime running processes.
  * `pstree` - List running processes in a tree.
