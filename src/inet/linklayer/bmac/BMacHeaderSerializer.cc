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
#include "inet/linklayer/bmac/BMacHeader_m.h"
#include "inet/linklayer/bmac/BMacHeaderSerializer.h"

namespace inet {

Register_Serializer(BMacHeader, BMacHeaderSerializer);

void BMacHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    B startPos = B(stream.getLength());
    const auto& bMacHeader = staticPtrCast<const BMacHeader>(chunk);
    stream.writeByte(B(bMacHeader->getChunkLength()).get());
    stream.writeMacAddress(bMacHeader->getSrcAddr());
    stream.writeMacAddress(bMacHeader->getDestAddr());
    stream.writeUint16Be(bMacHeader->getNetworkProtocol());
    stream.writeByte(bMacHeader->getType());
    if ((B(stream.getLength()) - startPos) > B(bMacHeader->getChunkLength()))
        throw cRuntimeError("BMacHeader length = %d smaller than required %d bytes, try to increase the 'headerLength' parameter", (int)B(bMacHeader->getChunkLength()).get(), (int)B(stream.getLength() - startPos).get());
    while (B(stream.getLength()) - startPos < B(bMacHeader->getChunkLength()))
        stream.writeByte('?');
}

const Ptr<Chunk> BMacHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    B startPos = stream.getPosition();
    auto bMacHeader = makeShared<BMacHeader>();
    uint8_t length = stream.readByte();
    bMacHeader->setChunkLength(B(length));
    bMacHeader->setSrcAddr(stream.readMacAddress());
    bMacHeader->setDestAddr(stream.readMacAddress());
    int16_t networkProtocol = stream.readUint16Be();
    bMacHeader->setNetworkProtocol(networkProtocol);
    bMacHeader->setType(static_cast<BMacType>(stream.readByte()));
    while (B(length) - (stream.getPosition() - startPos) > B(0))
        stream.readByte();
    return bMacHeader;
}

} // namespace inet

