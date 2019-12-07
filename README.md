Work in progress !  

# checkcertif_server

PHP server  
  
[See the main project](https://github.com/Oros42/checkcertif)  

## Requirement

nginx or apache  
php >= 7.2  
php-pear  
gnupg  
redis  

## Install

### Php
```
apt install php-common libgpgme11-dev php-pear php-dev php-redis

apt install php-cli
# or
apt install php

pecl install gnupg

for v in /etc/php/*; do echo "extension=gnupg.so" > $v/mods-available/gnupg.ini; done
phpenmod gnupg
```

Restart your webserver
```
systemctl restart apache2
```
or
```
systemctl restart nginx
```

```
cd /var/www/html

gpgHome="private"
mkdir -p $gpgHome
chown -R www-data $gpgHome
chmod 700 $gpgHome
#gpg-agent --daemon --homedir $gpgHome
```


### Redis
```
apt install redis
```
Default listen on 127.0.0.1:6379 and no password.  
I recommand you to setup a password!
  
in /etc/redis/redis.conf :
```
save 900 1
save 300 10
save 60 10000
```
become :
```
save ""
#save 900 1
#save 300 10
#save 60 10000
```

#### Test
```
<?php
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
//$redis->auth('myPassword');

$key='message';
$redis->set($key, 'Hello world');
$redis->expire($key, 1200);// 1200s == 20 min

echo $redis->get($key);
?>
```
https://github.com/phpredis/phpredis  
  

### GnuPG

```
email="<demo@example.com>" # change this
gpgHome="/<PATH_TO_SAFE_DIR>/" # change this to a safe place
mkdir -p $gpgHome
chmod 700 $gpgHome
gpg --batch --homedir $gpgHome --passphrase '' --quick-generate-key "$email" secp256k1 default 20y
gpg --homedir $gpgHome -a --export "$email" > public.gpg
chown -R www-data $gpgHome
```