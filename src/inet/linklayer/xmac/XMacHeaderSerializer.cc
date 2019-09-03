//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/linklayer/xmac/XMacHeader_m.h"
#include "inet/linklayer/xmac/XMacHeaderSerializer.h"

namespace inet {

Register_Serializer(XMacHeader, XMacHeaderSerializer);

void XMacHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    B startPos = B(stream.getLength());
    const auto& xMacHeader = staticPtrCast<const XMacHeader>(chunk);
    stream.writeByte(B(xMacHeader->getChunkLength()).get());
    stream.writeMacAddress(xMacHeader->getSrcAddr());
    stream.writeMacAddress(xMacHeader->getDestAddr());
    stream.writeUint16Be(xMacHeader->getNetworkProtocol());
    stream.writeByte(xMacHeader->getType());
    stream.writeUint64Be(xMacHeader->getSequenceId());
    if ((B(stream.getLength()) - startPos) > B(xMacHeader->getChunkLength()))
        throw cRuntimeError("XMacHeader length = %d smaller than required %d bytes, try to increase the 'headerLength' parameter", (int)B(xMacHeader->getChunkLength()).get(), (int)B(stream.getLength() - startPos).get());
    while ((B(stream.getLength()) - startPos) < B(xMacHeader->getChunkLength()))
        stream.writeByte('?');
}

const Ptr<Chunk> XMacHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    B startPos = stream.getPosition();
    auto xMacHeader = makeShared<XMacHeader>();
    uint8_t length = stream.readByte();
    xMacHeader->setChunkLength(B(length));
    xMacHeader->setSrcAddr(stream.readMacAddress());
    xMacHeader->setDestAddr(stream.readMacAddress());
    int16_t networkProtocol = stream.readUint16Be();
    xMacHeader->setNetworkProtocol(networkProtocol);
    xMacHeader->setType(static_cast<XMacTypes>(stream.readByte()));
    xMacHeader->setSequenceId(stream.readUint64Be());
    while (B(length) - (stream.getPosition() - startPos) > B(0))
        stream.readByte();
    return xMacHeader;
}

} // namespace inet

