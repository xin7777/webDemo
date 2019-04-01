<?php
	
$source_name = $_POST['input1'];
$source_loc = $_POST['input2'];
$source_local = $_POST['input3'];
$key_path = $_POST['input4'];
if(!file_exists($key_path)){
	echo "file $key_path is not exists" ;
	exit(1);
}
$cmd = "./client g ".$source_name." ".$source_loc." ".$key_path." ".$source_local ;
exec($cmd,$result,$status) ;
//echo $key_path ;
//echo $result[0] ;
//echo $result[1] ;
echo $result[3]." : " ;
echo $result[2]."" ;

?>
