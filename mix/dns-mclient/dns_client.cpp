#include "dns_client.h"


DNS_Client::DNS_Client(string resolv_file){
	ifstream infile(resolv_file.data(),ios::binary) ;
	if(!infile.is_open()){
		cout << " open file " << resolv_file << " error" << endl  ;
		exit(1);
	}

	string line ;
	string str1("nameserver");
	while(getline(infile,line)){
		int index1 = line.find(str1,0) + str1.length() ;
		index1 = line.find_first_not_of(" ",index1);
		int index2 = line.find_first_not_of(".0987654321",index1);
		//cout << line.substr(index1,index2-index1) << endl ;
		this->nameservers.push_back(line.substr(index1,index2-index1));
	}
	cout << "nameserver : " << this->nameservers[0] << endl ;
	infile.close();

	key_manager.init();
	key_manager.setKeyPair();
}

void DNS_Client::set_cer_path(string cer_path){
	this->cer_path = cer_path ;
}

void DNS_Client::storeKey(){
	string pubkey = this->key_manager.getPublicKey();
	int keylen = pubkey.length();
	FILE * file = fopen(this->cer_path.data() , "wb");
	if(file == NULL){
		cout << "1\n2\ncan not open file " << this->cer_path << endl ;
		exit(1);
	}
	fwrite(&keylen,sizeof(int),1,file);
	fwrite(pubkey.data(),sizeof(char),keylen,file);
	//cout << pubkey << endl ;
	string prikey = this->key_manager.getPrivateKey();
	//cout << prikey << endl ;
	keylen = prikey.length();
	fwrite(&keylen,sizeof(int),1,file);
	fwrite(prikey.data(),sizeof(char),keylen,file);
	fclose(file);
}

void DNS_Client::setKey(){
	FILE * file = fopen(this->cer_path.data() , "rb");
	if(file == NULL){
		cout << "1\n2\ncan not open file " << this->cer_path << endl ;
		exit(1);
	}
	//cout << "======================" << endl ;
	int keylen = 0;
	fread(&keylen,sizeof(int),1,file);
	char buff[1000];
	fread(buff,sizeof(char),keylen,file);
	buff[keylen]='\0';
	string pubkey = buff ;
	//cout << pubkey << endl ;
	this->key_manager.setPublicKey(pubkey);
	//cout << this->key_manager.getPublicKey() << endl ;
	fread(&keylen,sizeof(int),1,file);
	fread(buff,sizeof(char),keylen,file);
	buff[keylen]='\0';
	string prikey = buff ;
	//cout << prikey << endl ;
	this->key_manager.setPrivateKey(prikey);
	//cout << this->key_manager.getPrivateKey() << endl ;
	fclose(file);
	//cout << "======================" << endl ;
}

string getDocumentString(rapidjson::Value& d)
{
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);
	std::string str=buffer.GetString();
	return str;
}

string send2server_echo(string buff , string ip){
	
	boost::asio::io_service service;
	boost::asio::ip::address addr;
	addr = addr.from_string(ip);
	boost::asio::ip::tcp::socket sock(service);
	boost::asio::ip::tcp::endpoint ep(addr,8010);
	sock.connect(ep);
	
	sock.write_some(boost::asio::buffer(buff));
	char read_buff[8000] ;
	sock.read_some(boost::asio::buffer(read_buff));
	string result = read_buff ;
	return read_buff ;
}
int send2server_noecho(string buff , string ip){
	boost::asio::io_service service;
	boost::asio::ip::address addr;
	addr = addr.from_string("219.223.193.176");
	boost::asio::ip::tcp::socket sock(service);
	boost::asio::ip::tcp::endpoint ep(addr,8010);
	sock.connect(ep);
	sock.write_some(boost::asio::buffer(buff));
	return 0;
}

string get_file_hash(string filename){
	string result = "";
	return result ;
}

string DNS_Client::query(string source_name_ , int QueryCode_){
	
	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("Query",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value QueryCode(QueryCode_ );
	data.AddMember("QueryCode",QueryCode,allocator);
	rapidjson::Value NDN(source_name_.data(),allocator);
	if(QueryCode_ == 0 ) data.AddMember("NDN",NDN,allocator);
	else if(QueryCode_ == 1) data.AddMember("prefix" , NDN , allocator) ;
	
	result.AddMember("data",data,allocator);
	string query_string = getDocumentString(result);
	string response;
	response = send2server_echo(query_string.data(),this->nameservers[0]);
	return response;
}

string DNS_Client::generate(string source_name_ , string ip_ , string file_hash , string other_){
	
	this->setKey();
	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("Generate",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value NDN(source_name_.data(),allocator);
	data.AddMember("NDN",NDN,allocator);
	rapidjson::Value IP(ip_.data(),allocator);
	data.AddMember("IP",IP,allocator);
	rapidjson::Value pubkey(this->key_manager.getPublicKey().data(),allocator);
	data.AddMember("pubkey",pubkey,allocator);
	rapidjson::Value hash(file_hash.data() ,allocator);
	data.AddMember("hash",hash,allocator);
	rapidjson::Value timestamp((double)(unsigned)time(NULL));
	data.AddMember("timestamp",timestamp,allocator);
	rapidjson::Value other(other_.data(),allocator);
	data.AddMember("other",other , allocator);

	rapidjson::Value sig(this->key_manager.sign(this->key_manager.getHash256(getDocumentString(data))).data() ,allocator);
	result.AddMember("sig",sig,allocator);
	result.AddMember("data",data,allocator);
	string request_string = getDocumentString(result);
	string response;
	response = send2server_echo(request_string.data(),this->nameservers[0]);
	return response ;
}

string DNS_Client::registry(string prefix_ , int level_ , string real_msg_){
	
	key_manager.setKeyPair();
	this->storeKey();
	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("Registry",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value pubkey(this->key_manager.getPublicKey().data(),allocator);
	data.AddMember("pubkey",pubkey,allocator);
	rapidjson::Value prefix(prefix_.data(),allocator);
	data.AddMember("prefix",prefix,allocator);
	rapidjson::Value level(level_);
	data.AddMember("level",level,allocator);
	rapidjson::Value timestamp( (double)(unsigned)time(NULL));
	data.AddMember("timestamp",timestamp,allocator);
	rapidjson::Value real_msg(real_msg_.data(),allocator);
	data.AddMember("real_msg" , real_msg , allocator);

	string sig_str=this->key_manager.signDocument(data);
	rapidjson::Value sig(sig_str.data() ,allocator);
	result.AddMember("sig",sig,allocator);
	result.AddMember("data",data,allocator);
	string request_string = getDocumentString(result);
	cout<<request_string<<endl;

	string response;
	response = send2server_echo(request_string.data(),this->nameservers[0]);

	return response ;

}
string DNS_Client::get_user_data(int QueryCode_) {
	
	//this->setKey();
	//cout << this->key_manager.getPublicKey() << endl ;
	//cout << this->key_manager.getPrivateKey() << endl ;
	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("getUser",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value queryCode(QueryCode_ );
	data.AddMember("QueryCode", queryCode , allocator);
	rapidjson::Value pubkey(this->key_manager.getPublicKey().data(),allocator);
	data.AddMember("pubkey",pubkey,allocator);
	result.AddMember("data",data,allocator);
	string request_string = getDocumentString(result);
	string response;
	response = send2server_echo(request_string.data(),this->nameservers[0]);
	return response ;
}

string DNS_Client::update(string source_name_, string ip_) {

	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("Update",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value NDN(source_name_.data(),allocator);
	data.AddMember("NDN",NDN,allocator);
	rapidjson::Value IP(ip_.data(),allocator);
	data.AddMember("IP",IP,allocator);
	rapidjson::Value hash(get_file_hash("").data() ,allocator);
	data.AddMember("hash",hash,allocator);
	rapidjson::Value timestamp( (unsigned)time(NULL));
	data.AddMember("timestamp",timestamp,allocator);
	result.AddMember("data",data,allocator);
	rapidjson::Value sig(this->key_manager.sign(this->key_manager.getHash256(getDocumentString(data))).data() ,allocator);
	result.AddMember("sig",sig,allocator);
	string request_string = getDocumentString(result);
	string response;
	response = send2server_echo(request_string.data(), this->nameservers[0]);
	return response;
}

string DNS_Client::remove(string source_name_) {

	rapidjson::Document result;
	result.SetObject();
	rapidjson::Document::AllocatorType& allocator=result.GetAllocator();
	rapidjson::Value type("NDN-IP",allocator);
	result.AddMember("type",type,allocator);
	//构造data字段
	rapidjson::Value data;
	data.SetObject();
	rapidjson::Value command("Delete",allocator);
	data.AddMember("command",command,allocator);
	rapidjson::Value NDN(source_name_.data(),allocator);
	data.AddMember("NDN",NDN,allocator);
	rapidjson::Value timestamp( (unsigned)time(NULL));
	data.AddMember("timestamp",timestamp,allocator);
	result.AddMember("data",data,allocator);
	rapidjson::Value sig(this->key_manager.sign(this->key_manager.getHash256(getDocumentString(data))).data() ,allocator);
	result.AddMember("sig",sig,allocator);
	string request_string = getDocumentString(result);
	string response;
	response = send2server_echo(request_string.data(), this->nameservers[0]);
	return response;
}
