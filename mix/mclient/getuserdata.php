<?php
$key_path = $_POST['input1'];

if(!file_exists($key_path)){
	echo "file $key_path is not exist ";
	exit(1);
}

$cmd = "./client e ".$key_path ;
//echo $key_path ;
exec($cmd,$result,$status) ;
echo $result[2]." : " ;
if($result[2] == 601){
	echo "未注册成功\n" ;
}else if($result[2] == 600){
	echo "注册成功\n" ;
	if($result[3] == 1){
		echo "您注册的标识前缀为 : ".$result[4]."\n";
		echo "您可以在该前缀下发布您的网络资源\n";
	}else{
		echo "您注册的用户等级为0,不能发布资源\n " ;
	}
}
?>
