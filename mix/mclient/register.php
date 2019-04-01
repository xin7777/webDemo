<?php
	
$username = $_POST['input1'];
$phone_number = $_POST['input2'];
$prefix = $_POST['input3'];
$key_path = $_POST['input4'];
$real_name = $_POST['input5']
$id_card = $_POST['input6']
//echo $username ;
if($prefix[0] != '/'){
	echo "请求正确填写前缀名";
	exit(1);
}

$cmd = "./client r ".$prefix." ".$key_path ;
exec($cmd,$result,$status) ;
//echo $key_path ;
//echo $result[0] ;
//echo $result[1] ;
echo $result[3]." : " ;
echo $result[2]."\n\n" ;
if ($result[3] == 502) {
	echo "请修改您要申请的前缀名\n" ;
}
else if($result[3] == 500){
	echo "您可以在查询页面查询您的前缀申请状态\n" ;
}

?>
