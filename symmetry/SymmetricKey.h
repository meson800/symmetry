//Copyright (c) 2016 Christopher Johnstone(meson800)
//The MIT License - See ../LICENSE for more info
#pragma once

#include <vector>
#include <string>

struct SymmetricKey
{
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;

	std::string toString() const;
};
