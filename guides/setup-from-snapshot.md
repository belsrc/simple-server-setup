## Creating from an existing snapshot

Assuming that the snapshot was created after all items were configured from the main server setup file.


##### Update System
``` bash
apt-get update && apt-get upgrade
```


##### Change host name to domain

``` bash
hostname [DOMAIN].[TLD]
```

``` bash
nano /etc/hostname
```

Change the value in the file to the same as above.

##### Change host name in host file
``` bash
nano /etc/hosts
```

``` bash
127.0.0.1 localhost
127.0.0.1 [DOMAIN].[TLD] [DOMAIN].[TLD]
```

##### Change host name in mail local hosts
``` bash
nano /etc/mail/local-host-names
```

``` bash
localhost
[DOMAIN].[TLD]
```

##### Generate new Tripwire local key
``` bash
twadmin --generate-keys --local-keyfile /etc/tripwire/$HOSTNAME-local.key
```

##### Reinitialize Tripwire database with new key
``` bash
tripwire --init
```

##### Check Tripwire
``` bash
tripwire --check
```

##### Update RKHunter proposed
``` bash
rkhunter --propupd
```

##### Update New Relic Monitor
If your using the New Relic server monitor, you'll

``` bash
nano /etc/newrelic/nrsysmond.cfg
```
You'll need to change the license key and the host name
```
license_key=[LICENSE_KEY]
hostname=[HOST_NAME]
```
