#include <iostream>
#include <string>
#include <algorithm>

#include "Crypto.h"
#include "CryptoHelpers.h"
#include "Helpers.h"
#include "Log.h"
#include "base64.h"

int main()
{
	Log::setLogfile("symmetry.log");
	std::cout << "Enter key:";
	std::string key;
	std::string input;
	std::getline(std::cin, key);
#ifdef _WIN32
	std::system("cls");
#else
	// Assume POSIX
	std::system("clear");
#endif
	//derive key
	std::vector<unsigned char> pepper;
	pepper.push_back(0x62);
	pepper.push_back(0x6c);
	pepper.push_back(0x61);
	pepper.push_back(0x63);
	pepper.push_back(0x6b);
	pepper.push_back(0x65);
	pepper.push_back(0x72);
	pepper.push_back(0x0d);
	//init crypto and key
	Crypto crypto;
	SymmetricKey symKey = crypto.deriveKeyFromPassword(pepper, Helpers::stringToBytes(key));

	std::cout << "Enter e to encrypt, d to decrypt:";
	std::string op;
	std::getline(std::cin, op);

	op.erase(std::remove(op.begin(), op.end(), '\n'), op.end());
	std::vector<unsigned char> result;
	try
	{
		if (op[0] == 'e')
		{
			std::cout << "Enter text to encrypt:";
			std::getline(std::cin, input);
			result = crypto.encryptSymmetric(symKey, Helpers::stringToBytes(input));
		}
		else
		{
			std::cout << "Enter text to decrypt:";
			std::getline(std::cin, input);
			std::string inputBytes = base64_decode(input);
			result = crypto.decryptSymmetric(symKey, Helpers::stringToBytes(inputBytes));
			std::cout << "\n";
			for (unsigned int i = 0; i < result.size(); ++i)
				std::cout << result[i];
			std::cout << "\nPress enter to exit...\n";
			std::cout.flush();
			std::cin.ignore(std::numeric_limits <std::streamsize> ::max(), '\n');
			return 0;
		}

		std::cout << "\n";
		std::cout << base64_encode(result.data(), result.size());
	}
	catch (OpensslException)
	{
		std::cout << "Couldn't decrypt text. Either the key was bad or the data was corrupted/entered incorrectly :(\n";
	}
	std::cout << "\nPress enter to exit...\n";
	std::cout.flush();
	std::cin.ignore(std::numeric_limits <std::streamsize> ::max(), '\n');
	return 0;
}