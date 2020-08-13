#pragma once

#include <cstdint>
#include <string>
#include <netinet/in.h>


struct IpHdr final{ //이전과제 참고
      unsigned char Header_size:4;
      unsigned char Version:4;
      unsigned char Service;            //DSCP+ECN = 1바이트
      unsigned short Total_Length;      //2바이트
      unsigned short Identification;    //2바이트
      unsigned char Reserved_must_be_zero:1;
      unsigned char Dont_Fragment:1;
      unsigned char More_Fragment:1;
      unsigned char Fragment_Offset1:5;//13비트는 안되니 5비트+1바이트
      unsigned char Fragment_Offset2;
      unsigned char TTL;             //1바이트
      unsigned char Protocol;        //1바이트
      unsigned short Header_checksum;//2바이트
      uint32_t Src_add;        //4바이트
      uint32_t Dest_add;
    };



struct Ip final {
	static const int SIZE = 4;

	//
	// constructor
	//
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	//
	// casting operator
	//
	operator uint32_t() const { return ip_; } // default
	explicit operator std::string() const;

	//
	// comparison operator
	//
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }



protected:
	uint32_t ip_;
};
