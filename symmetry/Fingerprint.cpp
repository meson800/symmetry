#include "Fingerprint.h"
#include "Exceptions.h"
#include "Log.h"
#include "CryptoHelpers.h"
namespace openssl
{
#include <openssl/sha.h>
}

Fingerprint::Fingerprint()
{
}

Fingerprint::Fingerprint(openssl::EVP_PKEY * key)
{
	//Get public key of key
	std::vector<unsigned char> bytes = CryptoHelpers::oslPublicKeyToBytes(key);
	
	unsigned char * tempArray = new unsigned char[SHA_DIGEST_LENGTH];
	openssl::SHA1(bytes.data(), bytes.size(), tempArray);

	data = std::vector<unsigned char>(tempArray, tempArray + SHA_DIGEST_LENGTH);

	delete[](tempArray);
}

Fingerprint::Fingerprint(std::vector<unsigned char> _data, bool isArbitraryData) : data(_data)
{
	if (isArbitraryData)
	{
		data.clear();
		unsigned char * tempArray = new unsigned char[SHA_DIGEST_LENGTH];
		openssl::SHA1(_data.data(), _data.size(), tempArray);

		data = std::vector<unsigned char>(tempArray, tempArray + SHA_DIGEST_LENGTH);

		delete[](tempArray);
	}
	if (data.size() != SHA_DIGEST_LENGTH)
		throw std::runtime_error("Fingerprint data is not the right size");
}


//hexmap and code in toString taken from
//http://codereview.stackexchange.com/questions/78535/converting-array-of-bytes-to-the-hex-string-representation
//Because it's a lot faster than std::hex and friends (as explained in stackexchange link)
constexpr char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

std::string Fingerprint::toString() const
{
	if (data.size() == 0)
		throw std::runtime_error("Can't use empty fingerprint");
	std::string s(data.size() * 3 - 1, ' ');
	for (unsigned int i = 0; i < data.size(); ++i) {
		s[3 * i] = hexmap[(data[i] & 0xF0) >> 4];
		s[3 * i + 1] = hexmap[data[i] & 0x0F];
		if (i != data.size() - 1)
			s[3 * i + 2] = ':';
	}
	return s;
}

Fingerprint & Fingerprint::operator=(const Fingerprint & other)
{
	//only do assignent if it is a different object
	if (this != &other)
	{
		//the vector automatically cleans up in this assignment
		data = other.data;
	}
	return *this;
}

bool Fingerprint::operator<(const Fingerprint & other) const
{
	if (data.size() == 0)
		throw std::runtime_error("Can't use empty fingerprint");
	//do "alphabetical" comparison, e.g. compare first byte. If it is < other, return true, else return false.
	//only move on to next character if they are the same
	if (data.size() != other.data.size())
		throw FingerprintComparisonException("Fingerprints weren't the same size");
	for (unsigned int i = 0; i < data.size(); ++i)
	{
		if (data[i] < other.data[i])
			return true;
		else if (data[i] > other.data[i])
			return false;
		else if (data[i] == other.data[i])
		{
			//don't do anything, loop to the next byte
		}
	}
	//if we got here, they were equal
	return false;
}

bool Fingerprint::operator==(const Fingerprint & other) const
{
	if (data.size() == 0)
		throw std::runtime_error("Can't use empty fingerprint");
	if (data.size() != other.data.size())
		throw FingerprintComparisonException("Fingerprints weren't the same size");
	for (unsigned int i = 0; i < data.size(); ++i)
	{
		if (data[i] != other.data[i])
			return false;
	}
	return true;
}

bool Fingerprint::operator!=(const Fingerprint & other) const
{
	if (data.size() == 0)
		throw std::runtime_error("Can't use empty fingerprint");
	return !(*this == other);
}
