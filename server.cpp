//
//  Homomorphic encryption server 
//  server in C++
//  Binds REP socket to tcp://127.0.0.1:5555
//  @author: Miroslav Puskaric https://github.com/mpuskaric


#include <zmq.hpp>
#include <string>
#include <iostream>
#include "utils.h"
#include "server.h"

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>

#define sleep(n)	Sleep(n)
#endif

int main () {
	
	//OpenFHE
	CC cc;
	Public_Key PKey;
	Eval_Key MKey;
	CT ctext, res;
	
	std::vector<double> x2 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0};
	std::cout << " Server vector: " << x2 << std::endl;
	
	//  Prepare our context and socket
	zmq::context_t context (2);
	zmq::socket_t socket (context, zmq::socket_type::rep);
	socket.bind(server_1);
	
	while (true) {
		Message request;
        	zmq::message_t incoming;
		zmq::message_t outgoing;
		
		std::cout << std::endl << " Listening for incoming connections..." << std::endl;
        	socket.recv (incoming, zmq::recv_flags::none);
		std::memcpy(request.header, incoming.data(), sizeof(request.header));
		
		if (strcmp(request.header, subject(CText)) == 0) //#8
		{
			std::cout << " Ciphertext received " << std::endl;
			ctext  = receive_params<CT>(incoming);
			// Do some data processing
			CT res = multiply(cc, PKey, ctext, x2);
			outgoing =	prep_message<CT>(Result, res);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}

		else if	(strcmp(request.header, subject(PubKey)) == 0) //#4
		{
			std::cout << " Public Key received " << std::endl;
			PKey = receive_params<Public_Key>(incoming);
			std::cout << " Requesting Multiplication Key " << std::endl;
			outgoing = header_only(R_MultKey);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
		
		else if (strcmp(request.header, subject(MultKey)) == 0)	//#6
		{
			std::cout << " Multiplication Key received " << std::endl;
			receive_multkey(incoming, cc);
			std::cout << " Requesting Ciphertext " << std::endl;
			outgoing = header_only(R_CText);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
		
		else if (strcmp(request.header, subject(CryptoC)) == 0) //#2
		{
			std::cout << " Cryptocontext received " << std::endl;
			cc = receive_params<CC>(incoming);
			cc->ClearEvalMultKeys();
			std::cout << " Requesting Public Key " << std::endl;
			outgoing = header_only(R_PubKey);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
				
		else 
		{
			std::cout << "Unknown message..." << std::endl;
			std::exit(1);
		}

    }
    return 0;
}
