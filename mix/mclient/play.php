<?php

$source_name = $_POST['input1'];
$cmd = "./client -q ".$source_name." ndn" ;
exec($cmd,$result,$status) ;
$cmd2 ="ps -A | grep -w nfd" ; 
exec($cmd2,$result2,$status) ;
if($result[2] == 400){
	if( $result2[0] == "" ){
		echo "ip";
	}else{
		echo "nd";
	}
	$source_url = $result[3];
	if($source_url[0] == '/') {
		echo "nd".$source_url ;
	}else{
		echo "ip".$source_url;
	}
}else if($result[2] == 401){
	echo "401 : 找不到该标识" ;
}


?>
