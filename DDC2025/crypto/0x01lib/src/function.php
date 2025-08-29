<?php
// function.php

function encrypt($data, $key, $iv) {
    $padded = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $padded;
}

function decrypt($data, $key, $iv) {
    $decrypted = openssl_decrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);    
    $decrypted = preg_replace('/[\x00-\x1F\x7F-\xFF]/', '?', trim($decrypted));    
    return $decrypted;
}
?>
