#ifndef CLIENT_H_WGH
#define CLIENT_H_WGH
#include <iostream>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <chrono>
#include "KeyManager.h"
#include <boost/array.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio.hpp>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#define BUFF_SIZE 2000

using namespace std;

class DNS_Client{
	private :
		vector<string> nameservers ;
		string cer_path ;
		KeyManager key_manager ;
		
	public:
		DNS_Client(string resolv_file);
		string query(string source_name , int queryCode);
		string generate(string source_name , string ip , string file_hash , string other_);
		string registry(string prefix , int level , string real_msg);
		string get_user_data(int queryCode) ;
		string update(string source_name, string ip);
		string remove(string source_name);
		void set_cer_path(string file_path);
		void setKey();
		void storeKey();

};

#endif 
