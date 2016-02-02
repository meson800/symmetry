//Copyright (c) 2016 Christopher Johnstone(meson800)
//The MIT License - See ../../LICENSE for more info
//Edited from Ren Nyffenegger
//See base64.cpp for more information
#pragma once
#include <string>

std::string base64_encode(unsigned char const*, unsigned int len);
std::string base64_decode(std::string const& s);
