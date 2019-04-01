<?php

$url = $_POST['url'];
//$url="192.168.5.11/003.mkv";
list($ip,$filename) = explode('/',$url);
//$ip = "192.168.5.11" ;
//$filename = "003.mkv" ;
$cmd = "echo ./nc ./ndn_client_config.json ".$ip." 9758 ".$filename." > ./recv_client/cmd.txt" ;
exec($cmd,$result,$status) ;
echo "0 " ;

?>
