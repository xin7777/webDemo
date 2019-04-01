CPP = g++

client: *.cpp *.cc
	${CPP} -std=c++11 -o client *.cpp *.cc -ljsoncpp -lmbedcrypto -lmbedx509 -lboost_system


clean:
	rm -rf *.o client
