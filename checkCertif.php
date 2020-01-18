<?php
/**
 * Check SSL / TLS certif
 * php version >=7.1
 *
 * @author  Oros42 <oros.checkcrt@ecirtam.net>
 * @link    https://github.com/Oros42/checkcertif_server
 * @license CC0 Public Domain
 * @version 0.7
 * @date    2020-01-05
 */

class CheckCertif
{
    // Version
    const API_VERSION = "0.7";

    // Parameters

    /**
     * Enable debug
     *
     * @var bool $_debug Debug
     * true : print debug infos in $logFile
     * false : no debug
     */
    private $_debug = false;

    /**
     * Log file
     *
     * @var string $_logFile Path to the debug's file.
     * You have to disallow web users to access this file.
     */
    private $_logFile = "./debug.log";

    /**
     * GnuPG home
     *
     * @var string $_gnupgHome Path to the GnuPG's home
     * You have to disallow web users to access this folder.
     */
    private $_gnupgHome = "private";

    /**
     * Redis host
     *
     * @var string $_redisHost IP or socket for Redis
     * Documentation : https://github.com/phpredis/phpredis#connect-open
     * Example :
     * "127.0.0.1"
     * "unix://redis.sock"
     */
    private $_redisHost = "127.0.0.1";

    /**
     * Redis port
     *
     * @var int $_redisPort Redis' port or null if socket
     */
    private $_redisPort = 6379;

    /**
     * Redis password
     *
     * @var string $_redisPassword Redis' password or empty string
     */
    private $_redisPassword = "";

    /**
     * Banned ips
     *
     * @var array $_bannedIps Regex to exclude hosts of certificat's check
     * https://www.php.net/manual/en/reference.pcre.pattern.syntax.php
     */
    private $_bannedIps = [
        //FIXME
        //IPv4
        '^127\\..*$',
        '^0\\.0\\.0\\.0.*$',
        '^10\\..*$',
        '^172\\.(1[6-9]|2[0-9]|30|31)\\..*$',
        '^192\\.168\\..*$',
        //IPv6
        '^::1.*$',
        '^::1.*$',
        '^fc[0-9a-fA-F][0-9a-fA-F]:.*$',
        '^fd[0-9a-fA-F][0-9a-fA-F]:.*$',
        '^fe80:.*$',
        '^fe00::.*$',
        '^ff00::.*$',
        '^ff02::.*$',
        '^ff02::.*$'
    ];

    /**
     * Banned hosts
     *
     * @var array $_bannedHosts Regex to exclude hosts of certificat's check
     * https://www.php.net/manual/en/reference.pcre.pattern.syntax.php
     */
    private $_bannedHosts = [
        //domain
        '^.*\\.lan$',
        '^.*\\.local$',
        '^.*\\.localdomain$',
        '^.*localhost$',
        '^.*ip6-localnet$',
        '^.*ip6-mcastprefix$',
        '^.*ip6-allnodes$',
        '^.*ip6-allrouters$'
    ];

    // Don't change

    private $_id = "";
    private $_response = "";
    private $_gpg = null;
    private $_aesKey64 = "";
    private $_aesIV64 = "";
    private $_targetURL = "";
    private $_redis = null;
    private $_action = null;
    private $_clientApiVersion = null;

    /**
     * Construct
     */
    public function __construct()
    {
        if (!is_file("config_chkcrt.php")) {
            $debug = $this->_debug ? "true" : "false";
            $bannedIps = var_export($this->_bannedIps, true);
            $bannedHosts = var_export($this->_bannedHosts, true);
            file_put_contents(
                "config_chkcrt.php",
                <<<EOF
<?php
\$this->_debug = $debug;
\$this->_logFile = "$this->_logFile"; // Change the path
\$this->_gnupgHome = "$this->_gnupgHome"; // Path to GnuPG's home
\$this->_redisHost = "$this->_redisHost";
\$this->_redisPort = $this->_redisPort;
\$this->_redisPassword = "$this->_redisPassword"; //Don't forget to set a password !
\$this->_bannedIps = $bannedIps;
\$this->_bannedHosts = $bannedHosts;
EOF
            );
            die("Edit the conf file to your needs.");
        }
        include_once "config_chkcrt.php";

        if (!extension_loaded("redis")) {
            $this->_log("need redis");
            die("need redis!");//FIXME
        }
        $this->_id = getmypid().'_'.uniqid('', true);//FIXME
        $this->_initGPG();
    }

    /**
     * Process
     *
     * @param  string $GPGMessage The GPG message sent by the firefox plugin
     * @return bool
     */
    public function GPGMessageProcess(string $GPGMessage):bool
    {
        /*
        Possible json in the GPG message :
        {
            'pwd':<AES key>, //require
            'i':<AES iv>, //require
            'a':<'v'|''>, //optionnal
            'url':<url> //optionnal
            'v':<API version> //optionnal
        }
        */

        $this->_log("GPGMessageProcess start");
        if ($this->_decodeGPGMessage($GPGMessage)) {
            if ($this->_action) {
                $action = "_action".$this->_action;
                $this->$action();
            } else {
                $hash = $this->_getHashFormCache();
                $this->_log(
                    sprintf(
                        "getHashFormCache : %s",
                        json_encode($hash)
                    )
                );
                if (empty($hash)) {
                    $hash = $this->_getCertifHash();
                    $this->_log(
                        sprintf(
                            "setHashToCache : %s",
                            json_encode($hash)
                        )
                    );
                    $this->_setHashToCache($hash);
                }
                $this->_encodeResponse($hash);
            }
        }
        if (empty($this->_response)) {
            $this->_genFakeResponse();
        }
        $this->_log("GPGMessageProcess end");
        return true;
    }

    /**
     * Return the response for the firefox plugin
     *
     * @return string
     */
    public function getResponse():string
    {
        return $this->_response;
    }


    // Private


    /**
     * Display and log errors if $this->_debug is true
     *
     * @param  Throwable $e Error
     * @return string if $this->_debug is true, return the error's message
     */
    private function _showError(Throwable $e):string
    {
        if ($this->_debug === true) {
            $this->_log(
                sprintf(
                    "Error %s. In %s:%s",
                    $e->getMessage(),
                    $e->getFile(),
                    $e->getLine()
                )
            );
            return sprintf(
                "Error :<br><pre>%s\n\nIn %s:%s</pre>",
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            );
        } else {
            return "";
        }
    }

    /**
     * If $this->_debug is true, log message in $this->_logFile
     *
     * @param string $message Message
     */
    private function _log(string $message)
    {
        if ($this->_debug === true) {
            error_log(
                sprintf(
                    "%s; %s; %s\n",
                    date("Y-m-d H:i:s"),
                    $this->_id,
                    $message
                ),
                3,
                $this->_logFile
            );
        }
    }

    /**
     * Check if Gnupg is setup and load the key
     */
    private function _initGPG()
    {
        try {
            /*
             * If gnupg isn't setup but `enable_dl` is set to true in php.ini,
             * than you can download gnupg.so
             * (from https://pecl.php.net/package/gnupg)
             * and run :
             */
            //dl("gnupg.so");

            if (!extension_loaded("gnupg")) {
                die(
                    "Need to setup gnupg!<br>"
                    ."sudo apt-get install libgpgme11-dev php-pear php-dev<br>"
                    ."sudo pecl install gnupg<br>"
                    ."<br>"
                    .'And add "extension=gnupg.so" to php.ini in /etc/php/...'
                );
            }

            putenv('GNUPGHOME='.$this->_gnupgHome);

            $this->_gpg = new gnupg();
            $keys = $this->_gpg->keyinfo('');
            if (empty($keys)) {
                die($this->_showError("You have to create a GnuPG key!"));
            }
        } catch (Exception $e) {
            die($this->_showError($e));
        } catch (Error $e) {
            die($this->_showError($e));
        }
    }

    /**
     * Check if $server is valide for one regex of $list
     *
     * @param  array $list Regex array
     * @param  string $server Server
     * @return bool
     */
    private function _isInList($list, $server):bool
    {
        foreach ($list as $regex) {
            preg_match('/'.$regex.'/', $server, $matches);
            if (!empty($matches)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Check if $server is not in blacklists
     *
     * @param  string $server Server
     * @return bool
     */
    private function _isBlacklisted($server):bool
    {
        // Too many preg_match :-(

        // check characters
        $banChr = ['/', '\\', '..', '"', "'", '?', '<', '>', '$'];
        foreach ($banChr as $chr) {
            if (strpos($server, $chr) !== false) {
                return true;
            }
        }

        // check host
        if ($this->_isInList($this->_bannedHosts, $server)) {
            return true;
        }

        // check ip
        if ($this->_isInList($this->_bannedIps, $server)) {
            return true;
        }

        $results = @dns_get_record($server, DNS_A| DNS_AAAA, $authns, $addtl);
        if (empty($results)) {
            return true;
        }

        foreach ($results as $result) {
            if (isset($result['ip'])) {
                if ($this->_isInList($this->_bannedIps, $result['ip'])) {
                    return true;
                }
            } else {
                if ($this->_isInList($this->_bannedIps, $result['ipv6'])) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get '<server>:<port>' from an URL
     *
     * @param  string $url Url of the website
     * @return string '<server>:<port>'
     */
    private function _getDomain($url):string
    {
        $server = $port = "";
        try {
            // $msgArray['url'] == "https://en.wikipedia.org/wiki/URL"
            $url = preg_replace("!.*://!i", "", filter_var($url, FILTER_SANITIZE_URL));
            // $url == en.wikipedia.org/wiki/URL
            $parsedUrl = parse_url("https://" . $url);
            // $parsedUrl == ['scheme' => 'https', 'host' => 'en.wikipedia.org', 'path' => '/wiki/URL']
            $port = array_key_exists('port', $parsedUrl) ? $parsedUrl['port'] : "443";
            // $port == 443
            $server = $parsedUrl['host'];
            // $server == "en.wikipedia.org"

            if ($this->_isBlacklisted($server)) {
                return "";
            }
        } catch (Exception $e) {
            return "";
        }
        if ($server == "" || $port == "") {
            return "";
        } else {
            return $server.':'.$port;
        }
    }

    /**
     * Cleaning AesKey64
     *
     * @param string $s String
     * @return string
     */
    private function _cleaningAesKey64(string $s):string
    {
        try {
            if (strlen(base64_decode($s)) != 32) {
                return "";
            } else {
                return $s;
            }
        } catch (Exception $e) {
            return "";
        }
    }

    /**
     * Cleaning AesIV64
     *
     * @param string $s String
     * @return string
     */
    private function _cleaningAesIV64(string $s):string
    {
        return $s;
        /*
        try {
            if (strlen(base64_decode($s)) != 16) {
                return "";
            } else {
                return $s;
            }
        } catch (Exception $e) {
            return "";
        }
        */
    }

    /**
     * Cleaning Action
     *
     * @param string $s String
     * @return string
     */
    private function _cleaningAction(string $s):string
    {
        $r = "";
        switch ($s) {
            case 'v':
                $r = "Version";
                break;

            //For future actions

            default:
                break;
        }
        return $r;
    }

    /**
     * Decode the GPG message
     *
     * @param  string $GPGMessage GPG message
     * @return bool
     */
    private function _decodeGPGMessage(string $GPGMessage):bool
    {
        try {
            if (empty($GPGMessage)) {
                return false;
            }

            $this->_gpg->seterrormode(gnupg::ERROR_WARNING);

            if (strpos($GPGMessage, "-----BEGIN PGP MESSAGE-----") === false) {
                // add PGP header when it removed
                $GPGMessage = "-----BEGIN PGP MESSAGE-----\r\n"
                   ."Version: ...\r\n"
                   ."Comment: ...\r\n\r\n"
                   .$GPGMessage;
            }

            if (strpos($GPGMessage, "-----END PGP MESSAGE-----") === false) {
                // add PGP footer when it removed
                $GPGMessage .= "\r\n-----END PGP MESSAGE-----\r\n";
            }

            $msgString = $this->_gpg->decrypt($GPGMessage);
            $error = $this->_gpg->geterror();
            if (!$error && !empty($msgString)) {
                $this->_log("msgString : $msgString");
                $msgArray = @json_decode($msgString, true);
            } else {
                $this->_log("msgString error");
            }
        } catch (Throwable $e) {
            $this->_log($this->_showError($e));
            return false;
        }
        if ($error) {
            $this->_log("GunPG error : $error");
            return false;
        }

        // AES key
        if (!empty($msgArray['pwd'])) {
            $this->_aesKey64 = $this->_cleaningAesKey64($msgArray['pwd']);
            $this->_log("aesKey64 : ".$this->_aesKey64);
        }
        if (empty($this->_aesKey64)) {
            return false;
        }

        // AES iv
        if (!empty($msgArray['i'])) {
            $this->_aesIV64 = $this->_cleaningAesIV64($msgArray['i']);
            $this->_log("aesIV64 : ".$this->_aesIV64);
        }
        if (empty($this->_aesIV64)) {
            return false;
        }

        // action
        if (!empty($msgArray['a'])) {
            $this->_action = $this->_cleaningAction($msgArray['a']);
            $this->_log("action : ".$this->_action);
        }

        // URL
        if (!empty($msgArray['url'])) {
            $this->_targetURL = $this->_getDomain($msgArray['url']);
            if ($this->_targetURL === "") {
                $this->_log("error targetURL");
                return false;
            }
            $this->_log("targetURL : ".$this->_targetURL);
        }

        // Client API version
        if (!empty($msgArray['v'])) {
            $this->_clientApiVersion = $msgArray['v'];
        }

        if (empty($this->_action) && empty($this->_targetURL)) {
            return false;
        }

        return true;
    }

    /**
     * Generate fake response
     */
    private function _genFakeResponse()
    {
        $this->_log("genFakeResponse");
        if (empty($this->_aesKey64)) {
            $this->_aesKey64 = base64_encode(random_bytes(32));
        }
        if (empty($this->_aesIV64)) {
            $this->_aesIV64 = base64_encode(random_bytes(16));
        }
        $data = random_bytes(random_int(50, 100));
        $random = [
            'r0' => sha1($data),
            'r1' => hash('sha256', $data)
        ];
        if (!$this->_encodeResponse($random)) {
            $this->_response = base64_encode(random_bytes(random_int(160, 200)));
        }
    }

    /**
     * Encode the response
     *
     * @param  array $message Message
     * @return bool true if no error
     */
    private function _encodeResponse(array $message):bool
    {
        $cipher = "aes-256-gcm";
        if (in_array($cipher, openssl_get_cipher_methods())) {
            // To be sure that this message is uniq
            // if aesKey64 and aesIV64 are not change
            array_unshift($message, base64_encode(random_bytes(32)));

            $msg = json_encode($message);
            $this->_log("msg : $msg");

            if (phpversion() >= '7.1') {
                $m = @openssl_encrypt(
                    $msg,
                    $cipher,
                    base64_decode($this->_aesKey64),
                    OPENSSL_RAW_DATA,
                    base64_decode($this->_aesIV64),
                    $tag
                );
            } else {
                $tag="";
                $m = @openssl_encrypt(
                    $msg,
                    $cipher,
                    base64_decode($this->_aesKey64),
                    OPENSSL_RAW_DATA,
                    base64_decode($this->_aesIV64)
                );
            }
            if ($m) {
                if ($this->_clientApiVersion != null) {
                    $this->_response = base64_encode($m).';'.base64_encode($tag);
                } else {
                    // API <= 0.6
                    $this->_response = base64_encode($m.$tag);
                }
                $this->_log("response : ".$this->_response);
                return true;
            } else {
                return false;
            }
        } else {
            $this->_log("TODO : $cipher not found");
            die("TODO : $cipher not found");
        }
    }

    /**
     * Check if hashs are not in cache
     *
     * @return array If found : [1 =>'<sha1>',2 =>'<sha256>'] else []
     */
    private function _getHashFormCache():array
    {
        $this->_redis = new Redis(); // doc : https://github.com/phpredis/phpredis
        if ($this->_redisPort == null) {
            $this->_redis->connect($this->_redisHost);
        } else {
            $this->_redis->connect($this->_redisHost, $this->_redisPort);
        }
        if ($this->_redisPassword !== "") {
            $this->_redis->auth($this->_redisPassword);
        }
        $hashFromCache = $this->_redis->get($this->_targetURL);
        if ($hashFromCache) {
            $watchdog = 21;
            while ($watchdog > 0 && substr($hashFromCache, 0, 4) === "wait") {
                $watchdog--;
                usleep(100);
                $hashFromCache = $this->_redis->get($this->_targetURL);
                if (!$hashFromCache) {
                    $watchdog = -2;
                }
            }
            if ($watchdog >= 0 && substr($hashFromCache, 0, 4) !== "wait") {
                $this->_redis->close();
                return @json_decode($hashFromCache, true);
            }
        }
        $this->_redis->set($this->_targetURL, "wait ".$this->_id);
        $this->_redis->expire($this->_targetURL, 2);// 2s
        return [];
    }

    /**
     * Add hashs in cache
     *
     * @param array $hash Hashs like this [1 =>'<sha1>',2 =>'<sha256>']
     */
    private function _setHashToCache(array $hash)
    {
        $this->_redis->set($this->_targetURL, json_encode($hash));
        $this->_redis->expire($this->_targetURL, 1200);// 1200s == 20 min
        $this->_redis->close();
    }

    /**
     * Connect to the $this->_targetURL and get hashs of the certificate
     *
     * @return array If found : [1 =>'<sha1>',2 =>'<sha256>'] else []
     */
    private function _getCertifHash():array
    {
        $hash = [
            1 => '',
            2 => ''
        ];
        if (empty($this->_targetURL)) {
            return $hash;
        }

        // Thank to Thomas Gries and Tyler Romeo
        // for https://github.com/Wikinaut/MySimpleCertificateViewer

        $context = stream_context_create(
            [
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer'       => false
                ]
            ]
        );

        $timeout = 5;
        $errno = $errstr = 0;

        $this->_log("stream_socket_client ssl://".$this->_targetURL);

        $fp = @stream_socket_client(
            "ssl://".$this->_targetURL,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($fp === false) {
            $this->_log("connection error to targetURL. $errstr ($errno)");
            return $hash;
        }

        $params = @stream_context_get_params($fp);
        @fclose($fp);

        if (empty($params)) {
            $this->_log("no params");
            return $hash;
        }

        $cp = $params['options']['ssl']['peer_certificate'];

        $cert = '';
        @openssl_x509_export($cp, $cert);

        $cleanedCert = preg_replace('/\-+(BEGIN|END) CERTIFICATE\-+/', '', $cert);
        $cleanedCert = str_replace(array( "\n\r", "\n", "\r" ), '', trim($cleanedCert));
        $decCert = @base64_decode($cleanedCert);
        if (empty($decCert)) {
            $this->_log("can't get certificate");
            return $hash;
        }

        $hash[1] = sha1($decCert);
        $hash[2] = hash('sha256', $decCert);
        $this->_log("hash :".json_encode($hash));
        return $hash;
        /*
        Example of return for $this->_targetURL == en.wikipedia.org:443 (at 2019-10-13):
        hash == [
            "1":"06de14b2a922ef92f66b808114726023f8438199",
            "2":"8dcbfd60e96c79cff05c7f1752cf2b259d8841f94a221d2d8909d63d980ee60f"
        ]
        */
    }

    /**
     * Return the API's version
     */
    private function _actionVersion()
    {
        $this->_encodeResponse([
            'api' => self::API_VERSION
        ]);
    }
}
