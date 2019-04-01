#include <iostream>
#include "dns_client.h"
#include <boost/asio.hpp>
/*
 * contract :
 * standard output :
 * line1 : any
 * line2 : any
 * line3 : result code : int
 * 
 * 
 */
using namespace std;
using namespace rapidjson ;

DNS_Client client("./resolv.conf");


int main(int argc, char *argv[])
{
		boost::asio::io_service io_service;
		boost::asio::ip::tcp::socket tcp_socket(io_service);
		boost::asio::ip::tcp::endpoint local_add(boost::asio::ip::address::from_string("127.0.0.1"), 8010);

		if(argc < 2){
			cout << "Usage : ./client [-q|-g|-r|-e] " << endl ;
			cout << "Usage : ./client -q [name] [ndn/prefix]" << endl ;
			cout << "Usage : ./client -g [name] [loc_ip] [key_path] [hash_value] [other_msg]" << endl ;
			cout << "Usage : ./client -r [cer_path] [real_msg]" << endl ;
			cout << "Usage : ./client -r [prefix] [cer_path] [real_msg]" << endl ;
			cout << "Usage : ./client -e [cer_path]" << endl ;
			exit(1);
		}

		//cout << endl ;
		string cmd = argv[1];
		if(cmd == "-q"){
			// ./client -q [name] [ndn/prefix]
			string interest_name = argv[2];
			string query_type = argv[3];
			int queryCode = 0 ;
			if(query_type == "ndn") {
				queryCode = 0;
				string result =  client.query(interest_name, queryCode) ;
				Document doc ;
				doc.Parse<0>(result.c_str());
				Value & node1 = doc["msg"] ;
				Value & node2 = doc["StatusCode"] ;
				Value & node3 = doc["MsgType"] ;
				cout << result << endl ;
				int statusCode = node2.GetInt() ;
				cout << node2.GetInt() << endl ;
				if(statusCode == 400){
					Value & node4 = node1[0]["IP"];
					cout << node4.GetString() << endl ;
				}else if(statusCode == 401){
					cout << "找不到该标识" << endl ;
				}
			} else if (query_type == "prefix") { 
				queryCode = 1 ; 
				string result = client.query(interest_name, queryCode) ;
			}
			
		}
		else if(cmd == "-g"){
			// ./client -g [name] [loc] [cer_path] [local_source_path/hash_value] [other_msg]
			string source_name  = argv[2];
			string source_loc = argv[3];
			client.set_cer_path(argv[4]);
			string file_hash = argv[5];
			string other_msg = argv[6] ;
			string result =  client.generate(source_name,source_loc, file_hash , other_msg);
			cout << result << endl ;
			Document doc ;
			doc.Parse<0>(result.c_str());
			Value & node1 = doc["msg"] ;
			Value & node2 = doc["StatusCode"] ;
			cout << node1.GetString() << endl ;
			cout << node2.GetInt() << endl ;
		}
		else if(cmd == "-r"){
			int level = 0;
			if(argc == 4) {
				// ./client -r [cer_path] [real_msg]
				string real_msg = argv[3];
				client.registry("",level, real_msg);
				client.set_cer_path(argv[2]);
			}
			else{
				// ./client -r [prefix] [cer_path] [real_msg]
				string prefix = argv[2];
				level = 1 ;  // producer
				client.set_cer_path(argv[3]);
				string real_msg = argv[4] ;
				string result = client.registry(prefix,level,real_msg);
				//cout << result << endl ;
				Document doc ;
				doc.Parse<0>(result.c_str());
				Value & node1 = doc["msg"] ;
				Value & node2 = doc["StatusCode"] ;
				cout << node1.GetString() << endl ;
				cout << node2.GetInt() << endl ;
			}
		}
		else if(cmd == "-e"){
			// ./client -e [single|all] [key_path]
			string type = argv[2];
			if(type == "single")
			{
				client.set_cer_path(argv[3]);
				client.setKey();
				string result = client.get_user_data(0) ;
				cout<<"###" << result << endl ;
				Document doc ;
				doc.Parse<0>(result.c_str());
				Value & node1 = doc["msg"] ;
				Value & node2 = doc["StatusCode"] ;
				int statusCode = node2.GetInt() ;
				cout << statusCode << endl ;
				if(statusCode == 600){
					Value & node3 = node1["level"];
					int level = node3.GetInt() ;
					cout << level << endl ;
					if(level == 1){
						Value & node4 = node1["prefix"];
						cout << node4.GetString() << endl;
					}
				}
			}else if(type == "all"){
				string result = client.get_user_data(1) ;
				cout<<"###" << result << endl ;
			}
		}
	return 0;
}
