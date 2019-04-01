<?php

$url = $_POST['url'];
$cmd = "echo ./rcndn ".$url." > ./recv_client/cmd.txt" ;
exec($cmd,$result,$status) ;
echo "0 " ;

?>
