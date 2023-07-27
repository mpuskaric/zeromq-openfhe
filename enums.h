// 	message concept inspired by David Barr, aka javidx9, ©OneLoneCoder 2019, 2020 tutorials on networking 
//	and examples available in Palisade/OpenFHE repositories
//	@author: Miroslav Puskaric https://github.com/mpuskaric


#ifndef ENUMS_H
#include <string>
#include <iostream>

enum message
{
	//Send
	PubKey,
	MultKey,
	SummKey,
	RotKey,
	CText,
	Result,
	CryptoC,
	
	//Requests
	R_PubKey,
	R_MultKey,
	R_SummKey,
	R_RotKey,
	R_CText,
	R_CryptoC,
	
};

void get_subject(message state, char (&sub)[10]) 
{
	switch(state) {
				
		case PubKey: 	
			std::strcpy(sub, "PublicKey");
			break;
		case MultKey:	
			std::strcpy(sub, "MultipKey");
			break;
		case SummKey:	
			std::strcpy(sub, "SummatKey");
			break;
		case RotKey:	
			std::strcpy(sub, "RotatiKey");
			break;
		case CText:
			std::strcpy(sub, "CipherTex");
			break;
		case Result:	
			std::strcpy(sub, "EncResult");
			break;
		case CryptoC:
			std::strcpy(sub, "CryptoCon");
			break;
			
		case R_PubKey:
			std::strcpy(sub, "ReqPubliK");
			break;
		case R_MultKey:
			std::strcpy(sub, "ReqMultiK");
			break;
		case R_SummKey:
			std::strcpy(sub, "ReqSummaK");
			break;
		case R_RotKey:
			std::strcpy(sub, "ReqRotatK");
			break;
		case R_CText:
			std::strcpy(sub, "ReqCipheT");
			break;
		case R_CryptoC:
			std::strcpy(sub, "ReqCryptC");
			break;
			
		default:
			std::cout << "Error" << std::endl;
			std::exit(1);
	}
}

char* subject(message state)
{
	char* sub2 = new char[10];
	char sub[10];
	get_subject(state, sub);
	strcpy(sub2, sub);
	return sub2;
}

#endif