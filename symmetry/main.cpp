//Copyright (c) 2016 Christopher Johnstone(meson800)
//The MIT License - See ../LICENSE for more info
#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

#include "Crypto.h"
#include "CryptoHelpers.h"
#include "Helpers.h"
#include "Log.h"
#include "base64.h"

int main()
{
	Log::setLogfile("symmetry.log");
	std::cout << "Symmetry version 1.4\n";
	//std::cout << "Symmetry version 1.4\nEnter number of newlines to break on (or enter to use default of 2):\n";
	//std::string numNew;
	int maxNewlines = 3;
	//std::getline(std::cin, numNew);
	//if (numNew.size() == 0)
	//	maxNewlines = 3;
	//else
	//{
	//	std::istringstream buffer(numNew);
	//	buffer >> maxNewlines;
	//}

	std::cout << "Enter key: ";
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

	while (true)
	{
		std::cout << "Enter e to encrypt, d to decrypt, q to quit:";
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

				std::cout << "\n";
				std::cout << base64_encode(result.data(), result.size());
			}
			else if (op[0] == 'q')
			{
				return 0;
			}
			else
			{
				std::cout << "Enter text to decrypt. Terminate entry with " << maxNewlines << " consecutive newlines:";
				std::vector<std::string> inputLines;
				int numNewlines = 0;
				while (numNewlines < maxNewlines)
				{
					std::string newline;
					std::getline(std::cin, newline);
					if (newline.size() == 0)
						++numNewlines;
					else
					{
						numNewlines = 0;
						inputLines.push_back(newline);
					}

				}
				int numFailed = 0;
				for (std::string line : inputLines)
				{
					try
					{
						std::string inputBytes = base64_decode(line);
						result = crypto.decryptSymmetric(symKey, Helpers::stringToBytes(inputBytes));
						//if (numFailed > 0)
						//	std::cout << "\nCouldn't decrypt " << numFailed << " lines\n";
						//std::cout << "\n";
						//numFailed = 0;
						std::cout << "[PT]";
						for (unsigned int i = 0; i < result.size(); ++i)
							std::cout << result[i];
						std::cout << "\n";
					}
					catch (OpensslException)
					{
						std::cout << line << "\n";
						++numFailed;
					}
				}

			}


		}
		catch (OpensslException)
		{
			std::cout << "Couldn't decrypt text. Either the key was bad or the data was corrupted/entered incorrectly :(\n";
		}
		std::cout << "\nPress enter to continue...\n";
		std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
	}

	return 0;
}
