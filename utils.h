// @author: Miroslav Puskaric https://github.com/mpuskaric

#ifndef UTILS_H
#include <zmq.hpp>
#include <string>
#include <iostream>
#include "enums.h"

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

using CC = CryptoContext<DCRTPoly>;         // crypto context
using CT = Ciphertext<DCRTPoly>;            // ciphertext
using PT = Plaintext;                       // plaintext
using Key_Pair = KeyPair<DCRTPoly>;       	// secret/public key par.
using Eval_Key = EvalKey<DCRTPoly>;       	// evaluation key (reencryption key)
using Private_Key = PrivateKey<DCRTPoly>;	// secret key of par.
using Public_Key = PublicKey<DCRTPoly>;		// public key of par.
using vecInt = std::vector<int64_t>;		// vector of ints

struct Message {
	char header[10]; 
	std::string body;
};

//function for constructing a message 
template <typename T>
zmq::message_t prep_message(message header, T &to_serialize)
{
	std::string s;
	std::ostringstream os(s);
	Message tosend;
	
	strcpy(tosend.header, subject(header));	//subject
	Serial::Serialize(to_serialize, os, SerType::BINARY);
	tosend.body = os.str();		//body
	
	zmq::message_t msg( sizeof(tosend.header) + tosend.body.size() );
	std::memcpy(msg.data(), tosend.header, sizeof(tosend.header));
	std::memcpy((static_cast<char*>(msg.data())+sizeof(tosend.header)), tosend.body.data(), tosend.body.size());
	
	return msg;
}

void send_message(const char server[], zmq::message_t &msg)
{
	zmq::context_t context(1);
    	zmq::socket_t  socket(context, zmq::socket_type::req);
	zmq::message_t reply;
	Message received;
	
	std::cout << "Connecting to: " << server << std::endl;
	socket.connect(server);
	socket.send(msg, zmq::send_flags::none);
}

zmq::message_t header_only(message header)
{
	Message tosend;
	
	strcpy(tosend.header, subject(header));	//subject
	
	zmq::message_t msg( sizeof(tosend.header) + tosend.body.size() );
	std::memcpy(msg.data(), tosend.header, sizeof(tosend.header));
		
	return msg;
}

//function for receiving encryption keys or cryptocontext-ser
template <typename T>
T receive_params(zmq::message_t &msg)
{
	T param;
	Message message;
	
	std::memcpy(message.header, msg.data(), sizeof(message.header));
	std::istringstream is(std::string(static_cast<const char*>(msg.data())+ sizeof(message.header), static_cast<const char*>(msg.data()) + msg.size()));
	Serial::Deserialize(param, is, SerType::BINARY);
	
	return param;
}


zmq::message_t prep_multkey(message header, CC &cc)
{
	std::string s;
	std::ostringstream os(s);
	Message tosend;
	
	strcpy(tosend.header, subject(header));
	cc->SerializeEvalMultKey(os, SerType::BINARY);
	tosend.body = os.str();
	
	zmq::message_t msg( sizeof(tosend.header) + tosend.body.size() );
	std::memcpy(msg.data(), tosend.header, sizeof(tosend.header));
	std::memcpy((static_cast<char*>(msg.data())+sizeof(tosend.header)), tosend.body.data(), tosend.body.size());
	
	return msg;
}

void receive_multkey(zmq::message_t &msg, CC &cc)
{
	Message message;
	std::memcpy(message.header, msg.data(), sizeof(message.header));
	std::istringstream is(std::string(static_cast<const char*>(msg.data())+ sizeof(message.header), static_cast<const char*>(msg.data()) + msg.size()));
	cc->DeserializeEvalMultKey(is, SerType::BINARY);
}

#endif
