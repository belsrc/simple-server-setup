## SSH Log In Config
--------------------------------------------------------------

##### Add new user. [Enter strong pw and answer prompts]
``` bash
adduser [username]
```

##### Add user to sudo group [Run as root]
``` bash
gpasswd -a [username] sudo
```

##### Switch to the new user
``` bash
su - [username]
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
  * RSAAuthentication yes
  * PubkeyAuthentication yes

##### Disable root login [Add/change the following]
  * PermitRootLogin no

##### Disable password login [Add/change the following]
  * ChallengeResponseAuthentication no
  * PasswordAuthentication no
  * UsePAM no

##### Explicitly allow users [Add the following]
  * AllowUsers [username]

You can also allow groups by adding `AllowGroups [groupname]`

##### Save file and restart SSH
``` bash
service ssh restart
```

## Firewall
--------------------------------------------------------------

##### Check for UFW service
``` bash
service --status-all | grep "ufw"
```

##### Add SSH connections
``` bash
ufw allow ssh
```
Same as `ufw allow 22/tcp`. If changed ssh port use `ufw allow [ssh port]/tcp`

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
If changed ssh port use `ufw limit [ssh port]/tcp`

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
  * `ufw status numbered` to get a numbered list and then `ufw delete [number]` to delete a rule. `ufw delete [rule]` i.e `ufw delete allow ssh` can also be used
  * `ufw reset` to reset all rules

## Fail2Ban
--------------------------------------------------------------

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
ignoreip = 127.0.0.1/8 [ip_address]
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
destemail = [email_address]
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

Other useful commands
  * `fail2ban-client status` to get a list of enabled jails
  * `fail2ban-client status [jail_name]` to get more specific information
  * `fail2ban-client set nginx-http-auth unbanip [ip_address]`
  * `iptables -S` to see the iptable rules created

## Tripwire
--------------------------------------------------------------

[Soon™]

## Automatic Security Updates
--------------------------------------------------------------

[Soon™]

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

    server_name [server_host_name];

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
curl -sL https://deb.nodesource.com/setup_4.x | sudo bash -
```

##### Install node
``` bash
apt-get install nodejs
```

## MongoDB
--------------------------------------------------------------

[Soon™]

## Redis
--------------------------------------------------------------

[Soon™]