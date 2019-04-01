<?php

$url = $_POST['url'];
//$source_name = $_POST['input1'];
$cmd = "echo ./ndn_client ".$url." > ./recv_client/cmd.txt" ;
//$cmd = "echo ./ndn_client /test/aaa/testApp/003.mkv > ./recv_client/cmd.txt" ;
//$cmd = "echo /usr/bin/smplayer >./recv_client/cmd.txt" ;
exec($cmd,$result,$status) ;
echo "0 " ;
//echo $status ;
//echo $result[0];
//exec("whoami",$result,$status) ;
//echo $result[0] ;

?>
