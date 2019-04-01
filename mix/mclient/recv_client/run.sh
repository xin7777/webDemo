while [ 1 ]
do
	echo "hello"
	if [ -f "cmd.txt" ]
	then
		cmd=`cat ./cmd.txt`
		echo $cmd
		rm ./cmd.txt
		$cmd &
	fi
	sleep 1
done
