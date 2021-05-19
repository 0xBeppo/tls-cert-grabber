<?php 
    $filep = fopen("dump", "wb");
    $url = 'https://192.168.0.1';
    $ch = curl_init();
    // Check if initialization had gone wrong*    
    if ($ch === false) {
        throw new Exception('failed to initialize');
    }
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CERTINFO, true);
    curl_setopt($ch, CURLOPT_VERBOSE, true);
    curl_setopt($ch, CURLOPT_STDERR, $filep);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    if ($response === false) {
        throw new Exception(curl_error($ch), curl_errno($ch));
    }
    curl_close($ch);
?>