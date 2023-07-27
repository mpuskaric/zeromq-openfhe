//
//  Homomorphic encryption client 
//  Connects REQ socket to tcp://127.0.0.1:5555
//  @author: Miroslav Puskaric https://github.com/mpuskaric


#include <string>
#include <iostream>
#include "utils.h"

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>

#define sleep(n)	Sleep(n)
#endif

int main ()
{
	char sub[10];
	//ZeroMQ
	zmq::context_t context(1);
    	zmq::socket_t socket (context, zmq::socket_type::req);
	
	//OpenFHE	
	uint32_t multDepth = 5;
	uint32_t scaleFactorBits = 50;
	uint32_t batchSize = 8;
	
	SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
	CCParams<CryptoContextCKKSRNS> parameters;
    	parameters.SetMultiplicativeDepth(multDepth);
    	parameters.SetScalingModSize(scaleFactorBits);
	parameters.SetKeySwitchTechnique(HYBRID); 		
	parameters.SetScalingTechnique(FLEXIBLEAUTO); 	//FIXEDMANUAL FLEXIBLEAUTO
    	parameters.SetBatchSize(batchSize);
	//parameters.SetSecurityLevel(HEStd_128_classic);

	CC cc = GenCryptoContext(parameters);

	cc->Enable(PKE);
	cc->Enable(KEYSWITCH);
	cc->Enable(FHE);
	cc->Enable(LEVELEDSHE); //EvalMultKeyGen
	cc->Enable(ADVANCEDSHE); //EvalSumKeyGen
	
	Key_Pair kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);
	
	CT result;
	PT decrypted;
	
	std::vector<double> x1 = {0.5, 0.75, 1.12, 2.12, 3.12, 4.12, 5.12};
	PT ptxt = cc->MakeCKKSPackedPlaintext(x1);
	CT ctxt = cc->Encrypt(ptxt,kp.publicKey);
	
	std::cout << " Client vector: " << x1 << std::endl;
	
	// Workflow: CC -> PubKey -> MultKey -> CText
	zmq::message_t msg = prep_message<CC>(CryptoC, cc); //#1
	
	//ZeroMQ
    	std::cout << " Connecting to server..." << std::endl;
    	socket.connect("tcp://127.0.0.1:5555");
	std::cout << std::endl << " Sending first message..." << std::endl;
	socket.send(msg, zmq::send_flags::none);
	
	while (true)
	{
		zmq::message_t incoming;
		zmq::message_t outgoing;
		Message response;
		
		std::cout << std::endl << " Waiting for the reply..." << std::endl;
		socket.recv (incoming, zmq::recv_flags::none);
		
		std::memcpy(response.header, incoming.data(), sizeof(response.header));

		if (strcmp(response.header, subject(Result)) == 0) //#9
		{
			result = receive_params<CT>(incoming);
			std::cout << " Result received! " << std::endl;
			break;
		}
		
		else if (strcmp(response.header, subject(R_PubKey)) == 0) //#3
		{
			std::cout << " Public Key requested " << std::endl;
			outgoing = prep_message<Public_Key>(PubKey, kp.publicKey);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
		
		else if (strcmp(response.header, subject(R_CText)) == 0)  //#7
		{
			std::cout << " Ciphertext requested " << std::endl;
			outgoing = prep_message<CT>(CText, ctxt);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
		
		else if (strcmp(response.header, subject(R_MultKey)) == 0) //#5
		{
			std::cout << " Multiplication Key requested " << std::endl;
			outgoing = prep_multkey(MultKey, cc);
			socket.send(outgoing, zmq::send_flags::none);
			continue;
		}
		
		else
		{
			std::cout << "Unknown message..." << std::endl;
			std::exit(1);
		}

	}
	
	std::cout << std::endl << " Disconnecting from server..." << std::endl;
	socket.disconnect("tcp://127.0.0.1:5555");
	
	std::cout << std::endl << " Decryption..." << std::endl;
	cc->Decrypt(kp.secretKey, result, &decrypted);
	std::vector<std::complex<double>> finalResult = decrypted->GetCKKSPackedValue();
	finalResult.resize(batchSize);
	std::cout << " Result: " << finalResult << std::endl;
	
    return 0;
	
}
