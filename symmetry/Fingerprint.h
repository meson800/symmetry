//Copyright (c) 2016 Christopher Johnstone(meson800)
//The MIT License - See ../LICENSE for more info
#pragma once

#include <vector>
#include <string>

//forward declarations
namespace openssl
{
	struct evp_pkey_st;
	typedef evp_pkey_st EVP_PKEY;
}

class Fingerprint
{
public:
	//calculates fingerprint of given key
	Fingerprint();
	Fingerprint(openssl::EVP_PKEY* key);
	Fingerprint(std::vector<unsigned char> _data, bool isArbitraryData = false);
	//Returns fingerprint in human readable form
	std::string toString() const;

	//operators
	Fingerprint& operator=(const Fingerprint &other);
	bool operator<(const Fingerprint &other) const;
	bool operator==(const Fingerprint &other) const;
	bool operator!=(const Fingerprint &other) const;
	std::vector<unsigned char> data;

};
