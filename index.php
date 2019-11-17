<?php
if (!empty($_POST['m'])) {
    include "checkCertif.php";
    $CheckCertif = new CheckCertif();
    $CheckCertif->GPGMessageProcess($_POST['m']);
    echo $CheckCertif->getResponse();
    if (isset($_GET['debug'])) {
        echo $CheckCertif->getDebug();
    }
}
