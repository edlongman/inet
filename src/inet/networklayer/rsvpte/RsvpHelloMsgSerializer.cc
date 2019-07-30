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
#include "inet/networklayer/rsvpte/RsvpHelloMsg_m.h"
#include "inet/networklayer/rsvpte/RsvpHelloMsgSerializer.h"

namespace inet {

Register_Serializer(RsvpHelloMsg, RsvpHelloMsgSerializer);

void RsvpHelloMsgSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    throw cRuntimeError("LinkStatePacketSerializer not fully implemented yet.");
    const auto& rsvpHelloMsg = staticPtrCast<const RsvpHelloMsg>(chunk);
    std::cout << "B(rsvpHelloMsg->getChunkLength()): " << B(rsvpHelloMsg->getChunkLength()) << endl;
}

const Ptr<Chunk> RsvpHelloMsgSerializer::deserialize(MemoryInputStream& stream) const
{
    auto rsvpHelloMsg = makeShared<RsvpHelloMsg>();
    return rsvpHelloMsg;
}

} // namespace inet

