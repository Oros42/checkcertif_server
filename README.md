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
```bash
apt install php-common libgpgme11-dev php-pear php-dev php-redis

apt install php-cli
# or
apt install php

pecl install gnupg

for v in /etc/php/*; do echo "extension=gnupg.so" > $v/mods-available/gnupg.ini; done
phpenmod gnupg
```

Restart your webserver
```bash
systemctl restart apache2
```
or
```bash
systemctl restart nginx
```

```bash
cd /var/www/html # change this to your config
wget -q https://raw.githubusercontent.com/Oros42/checkcertif_server/master/checkCertif.php
wget -q https://raw.githubusercontent.com/Oros42/checkcertif_server/master/config_chkcrt.php.dist -O config_chkcrt.php
# you can copy the code of the index.php in an other file if you want
wget -q https://raw.githubusercontent.com/Oros42/checkcertif_server/master/index.php
```
Edit config_chkcrt.php for your config.  


### Redis
```bash
apt install redis
```
Default listen on 127.0.0.1:6379 and no password.  
 
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
I recommand you to setup a password!  
```
requirepass <your_pass>
```

```
systemctl restart redis
```

#### Test
```php
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

```bash
cd /var/www/html # change this to your config
email="<demo@example.com>" # change this
gpgHome="/<SAFE_DIR_PATH>/" # change this to a safe place
mkdir -p $gpgHome
chmod 700 $gpgHome
export GNUPGHOME=$gpgHome
gpg --batch --passphrase '' --quick-generate-key "$email" secp256k1 cert 20y
FPR=$(gpg -k $email|head -n 2|tail -n 1|awk '{print $1}')
gpg --batch --passphrase '' --quick-add-key $FPR secp256k1 encrypt 1y
gpg -a --export "$email" > public.gpg
chown -R www-data $gpgHome
```

## Test
  
Tests are here : https://github.com/Oros42/checkcertif/tree/master/tests  
