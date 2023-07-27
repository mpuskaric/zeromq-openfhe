//	@author: Miroslav Puskaric https://github.com/mpuskaric

#ifndef SERVER_H
#include <string>
#include <iostream>
#include "openfhe.h"

const char server_1[] = "tcp://127.0.0.1:5555";

CT multiply(CC &cc, Public_Key &pKey, CT &c1, std::vector<double> &x2) 
{
	PT p2;
	CT result, c2;
	std::cout << " Homomorphic multiplication of client and server vectors " << std::endl;
	p2 = cc->MakeCKKSPackedPlaintext(x2);
	c2 = cc->Encrypt(p2, pKey);
	result = cc->EvalMult(c1,c2);
	return result;
}

#endif