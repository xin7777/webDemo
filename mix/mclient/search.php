<?php

	$cmd = "./client -e all";
	exec($cmd,$result,$status);
	
	$data_result = substr($result[1],3,strlen($result[1])-1)


	$list = array();
	
	foreach( $data_result as $k => $v){
		if( $k == "msg"){
			$msg = $v;
		}
	}

	foreach( $msg as $each){
		foreach($each as $k => $v){
			if( $k == "real_msg"){
				array_push($list,$v);
			}
		}
	}


	/*±Í«©œ‘ æ*/
	foreach($list as $name){
		$name_array = explode(",",$name);
		$first_name = $name_array[0];
		$remark = $name_array[1];
		echo '
  		<div class="con">
      		      <div>
           		     <a href="https://dumall.baidu.com/?utm_source=baidu&utm_medium=all-products" class="abg xiaodu"
           		        target="_blank"></a>
         		   </div>
        		    <div>
        		        <a href="https://dumall.baidu.com/?utm_source=baidu&utm_medium=all-products" target="_blank">'.$first_name.'</a>
       		         <br/>
       		         <span>'.$remark.'</span>
       		     </div>
        </div>
		'
	}


?>









