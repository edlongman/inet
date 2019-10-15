//
// This library is free software, you can redistribute it
// and/or modify
// it under  the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation;
// either version 2 of the License, or any later version.
// The library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU Lesser General Public License for more details.
//


import inet.common.INETDefs;
import inet.common.packet.chunk.Chunk;
import inet.networklayer.contract.ipv4.Ipv4Address;
import inet.networklayer.common.L3Address;

namespace inet;

//
// LDP message types
//
enum LdpMessageTypes
{

    NOTIFICATION = 10;
    HELLO = 11;
    INITIALIZATION = 12;
    KEEP_ALIVE = 13;
    ADDRESS = 14;
    ADDRESS_WITHDRAW = 15;
    LABEL_MAPPING = 16;
    LABEL_REQUEST = 17;
    LABEL_WITHDRAW = 18;
    LABEL_RELEASE = 19;
    UNKNOWN = 20;
}

//
// TLV types
//
//# FIXME currently unused
enum TlvTypes
{
    FEC = 0x0100;
    GENERIC_LABEL = 0x0200;
    ATM_LABEL = 0x0201;
    FRAME_RELAY_LABEL = 0x0202;
    ADDRESS_LIST = 0x0101;
    HOP_COUNT = 0x0103;
    PATH_VECTOR = 0x0104;
    STATUS = 0x0300;
    COMMON_HELLO_PARMS = 0x0400;
}

//
// FEC Element type names
//
//# FIXME currently unused
enum FecTypes
{
    WILDCARD = 0x01;
    PREFIX = 0x02;
}

enum LdpStatusTypes
{

    NO_ROUTE = 13;
}

struct FecTlv
{
    Ipv4Address addr;
    int length;
}

//
// RFC 5036, 3.4.1. FEC TLV: FEC Element
// 
//# FIXME currently unused
class FecElement
{
 	uint8_t elementType;	// 8 bits, defines the type of the FEC Element
}

//
// RFC 5036, 3.4.1. FEC TLV: Wildcard FEC Element
// 
//# FIXME currently unused
class Wildcard extends FecElement
{
 	elementType = WILDCARD;
}

//
// RFC 5036, 3.4.1. FEC TLV: Prefix FEC Element
// 
//# FIXME currently unused
class Prefix extends FecElement
{
 	elementType = PREFIX;
 	uint16_t addressFamily;	// 16 bits, contains the ADDRESS FAMILY NUMBER that encodes the address family for the address prefix in the Prefix field
 	uint8_t preLen;	// 8 bits, contains the length in bits of the address prefix that follows
 	L3Address prefix;	// preLen bits long address prefix, padded to byte boundary
}

//
// RFC 5036, 3.3. Type-Length-Value Encoding
// Base class for TLVs
//
//# FIXME currently unused
class Tlv
{
    bool u;	// 1 bit, unknown TLV bit
    bool f;	// 1 bit, forward TLV bit
    uint16_t tlvType;	// 14 bits, encodes how the Value field is to be interpreted
    uint16_t tlvLength;	// 16 bits, length of the Value field in octets
}

//
// RFC 5036, 3.4.1. FEC TLV
//
//# FIXME currently unused
class TmpFecTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = FEC;
    FecElement fecElements[];
}

//
// RFC 5036, 3.4.2.1. Generic Label TLV, more details in RFC 3032, 2.1.
//
//# FIXME currently unused
class GenericLabelTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = GENERIC_LABEL;
    uint32_t label;	// 20 bits, Label Value
    uint8_t exp;	// 3 bits, Experimental Use (reserved for experimental use)
    bool s;			// 1 bit, Bottom of the Stack (set to one for the last entry in the labe stack)
    uint8_t ttl;	// 8 bits, Time to Live
}

//
// RFC 5036, 3.4.2.2. ATM Label TLV
//
//# FIXME currently unused
class AtmLabelTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = ATM_LABEL;
	uint8_t res = 0;	// 2 bits, reserved, set to zero
	uint8_t v;	// 2 bits, switching indicator
	uint16_t vpi;	// 12 bits, Virtual Path Identifier
	uint16_t vci;	// 16 bits, Virtual Channel Identifier
}

//
// RFC 5036, 3.4.2.3. Frame Relay Label TLV
//
//# FIXME currently unused
class FrameRelayLabelTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = FRAME_RELAY_LABEL;
	uint8_t res = 0;	// 7 bits, reserved, set to zero
	uint8_t len;	// 2 bits, specifies the number of bits of the DLCI (0: 10 bits, 1: reserved, 2: 23 bits, 3: reserved
	uint32_t dlci;	// 10 or 23 bits, Data Link Connection Identifier (if 10 bits long, then the first 13 bits are set to 0)
}

//
// RFC 5036, 3.4.3. Address List TLV
//
//# FIXME currently unused
class AddressListTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = ADDRESS_LIST;
    uint16_t addressFamily;	// 16 bits, value from ADDRESS FAMILY NUMBERS that encodes the addresses contained in the Addresses field
    L3Address addresses[];	// a list of addresses from the specified Address Family
}

//
// RFC 5036, 3.4.4. Hop Count TLV
//
//# FIXME currently unused
class HopCountTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = HOP_COUNT;
	uint8_t hcValue;	// 1 octet unsigned integer hop count value
}

//
// RFC 5036, 3.4.5. Path Vector TLV
//
//# FIXME currently unused
class PathVectorTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = PATH_VECTOR;
	uint64_t lsrId[];	// one or more 64 bits LSD ID fields
}

//
// RFC 5036, 3.4.6. Status TLV
//
//# FIXME currently unused
class StatusTlv extends Tlv
{
    tlvType = STATUS;
	bool e;	// 1 bit, fatal error bit (followed by th f bit again)
	uint32_t statusData;	// 30 bits, uinsigned integer that specifies the status information
	uint32_t messageId;	// 32 bits, if non-zero, identifies the peer message to which the Status TLV refers, if zero, no specific peer message is being identified
	uint16_t messageType;	// 32 bits, if non-zero, the type of the peer message to which the Status TLV refers, if zero, the Status TLV does not refer to any specific message type
}

//
// RFC 5036, 3.5.2. Common Hello Parameters TLV
//
//# FIXME currently unused
class CommonHelloParmsTlv extends Tlv
{
    u = false;
    f = false;
    tlvType = COMMON_HELLO_PARMS;
    uint16_t holdTime;	// 16 bits, Hello hold time in seconds, 0 means the default value -> 15secs for Link Hellos and 46secs for Targeted Hellos
    bool t;	// 1 bit, targeted hello, value of 1 specifies that this Hello is a Targeted Hello, 0 specifies that this Hello is a Link Hello
    bool r;	// 1 bit, request send targeted hellos, A value of 1 requests the receiver to send periodic Targeted Hellos to the source of this Hello.  A value of 0 makes no request.
    uint16_t reserved = 0;	// 14 bits, set to zero
}

//
// Base class for LDP packets.
// RFC 5036, 3.5. LDP Message
//
class LdpPacket extends FieldsChunk
{
    int type;
    Ipv4Address senderAddress;
    Ipv4Address receiverAddress;
    
    // according to (rfc5036)
    //
    // bool u;	// Unknown message bit
    // uint16_t msgType;	// 15 bits (identifies the type of the message)
    // uint16_t msgLength;	// 16 bits (length of the packet in bytes NOT including the u bit, msg type and msg length fields)
    // uint32_t msgId;	// 32 bits (used to identify the message)
    // Tlv *mandatoryParams;
    // Tlv *optionalParams;
}


//
// LDP Label Mapping Message
//
class LdpLabelMapping extends LdpPacket
{
    FecTlv fec;
    int label;
}

//
// LDP Label Request Message
//
class LdpLabelRequest extends LdpPacket
{
    FecTlv fec;
}


//
// RFC 5036, 3.5.2. Hello Message
//
class LdpHello extends LdpPacket
{
    CommonHelloParmsTlv commonHelloParmsTlv;
    Tlv optionalParameters[];
    
    // according to (rfc5036)
    //
    // msgType = 0x0100;
}

//
// RFC 5036, 3.5.1. Notification Message
//
class LdpNotify extends LdpPacket
{
    //StatusTlv statusTlv;
    //Tlv optionalParameters[];
    int status;
    FecTlv fec;
    
    // according to (rfc5036)
    //
    // msgType = 0x0001;
}

//
// RFC 5036, 3.5.3. Initialization Message
//
//# FIXME currently unused
class LdpIni extends LdpPacket
{
    double keepAliveTime;
    bool abit;
    bool dbit;
    int pvLim;
    string receiverLDPIdentifier;
    
    // according to (rfc5036)
    //
    // msgType = 0x0200;
}

//
// LDP Address Message
//
//# FIXME currently unused
class LdpAddress extends LdpPacket
{
    bool isWithdraw;
    string family;
    string addresses[];
}



