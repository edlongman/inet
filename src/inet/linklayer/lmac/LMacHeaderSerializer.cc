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
#include "inet/linklayer/lmac/LMacHeader_m.h"
#include "inet/linklayer/lmac/LMacHeaderSerializer.h"

namespace inet {

Register_Serializer(LMacHeader, LMacHeaderSerializer);

void LMacHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    B startPos = B(stream.getLength());
    const auto& lMacHeader = staticPtrCast<const LMacHeader>(chunk);
    stream.writeMacAddress(lMacHeader->getSrcAddr());
    stream.writeMacAddress(lMacHeader->getDestAddr());
    stream.writeUint16Be(lMacHeader->getNetworkProtocol());
    stream.writeByte(lMacHeader->getType());
    stream.writeUint64Be(lMacHeader->getMySlot());
    for (size_t i = 0; i < lMacHeader->getOccupiedSlotsArraySize(); ++i) {
        stream.writeMacAddress(lMacHeader->getOccupiedSlots(i));
    }
    while (B(stream.getLength()) - startPos < B(lMacHeader->getChunkLength()))
        stream.writeByte('?');
}

const Ptr<Chunk> LMacHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    auto lMacHeader = makeShared<LMacHeader>();
    lMacHeader->setChunkLength(stream.getRemainingLength());
    lMacHeader->setSrcAddr(stream.readMacAddress());
    lMacHeader->setDestAddr(stream.readMacAddress());
    lMacHeader->setNetworkProtocol(stream.readUint16Be());
    lMacHeader->setType(static_cast<LMacType>(stream.readByte()));
    lMacHeader->setMySlot(stream.readUint64Be());
    size_t i = 0;
    while (stream.getRemainingLength().get() > 0) {
        lMacHeader->setOccupiedSlotsArraySize(i + 1);
        lMacHeader->setOccupiedSlots(i, stream.readMacAddress());
        ++i;
    }
    while (B(stream.getRemainingLength()) > B(0))
        stream.readByte();
    return lMacHeader;
}

} // namespace inet

