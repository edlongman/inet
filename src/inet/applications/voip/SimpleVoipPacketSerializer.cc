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
#include "inet/applications/voip/SimpleVoipPacket_m.h"
#include "inet/applications/voip/SimpleVoipPacketSerializer.h"

namespace inet {

Register_Serializer(SimpleVoipPacket, SimpleVoipPacketSerializer);

void SimpleVoipPacketSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    B startPos = B(stream.getLength());
	const auto& simpleVoipPacket = staticPtrCast<const SimpleVoipPacket>(chunk);
	uint16_t totalLengthField = simpleVoipPacket->getTotalLengthField();
	if (totalLengthField < 30)
	    throw cRuntimeError("totalLengthField is smaller than required (30), try to increase the talkPacketSize parameter.");
	stream.writeUint16Be(totalLengthField);
	stream.writeUint32Be(simpleVoipPacket->getTalkspurtID());
	stream.writeUint32Be(simpleVoipPacket->getTalkspurtNumPackets());
	stream.writeUint32Be(simpleVoipPacket->getPacketID());
	stream.writeUint64Be(simpleVoipPacket->getVoipTimestamp().inUnit(SIMTIME_MS));
	stream.writeUint64Be(simpleVoipPacket->getVoiceDuration().inUnit(SIMTIME_MS));
	while (B(stream.getLength()) - startPos < B(totalLengthField))
	    stream.writeByte('?');
}

const Ptr<Chunk> SimpleVoipPacketSerializer::deserialize(MemoryInputStream& stream) const
{
    B startPos = B(stream.getPosition());
	auto simpleVoipPacket = makeShared<SimpleVoipPacket>();
	uint16_t totalLengthField = stream.readUint16Be();
	simpleVoipPacket->setTotalLengthField(totalLengthField);
	simpleVoipPacket->setChunkLength(B(totalLengthField));
	simpleVoipPacket->setTalkspurtID(stream.readUint32Be());
	simpleVoipPacket->setTalkspurtNumPackets(stream.readUint32Be());
	simpleVoipPacket->setPacketID(stream.readUint32Be());
	simpleVoipPacket->setVoipTimestamp(SimTime(stream.readUint64Be(), SIMTIME_MS));
	simpleVoipPacket->setVoiceDuration(SimTime(stream.readUint64Be(), SIMTIME_MS));
	while (B(stream.getPosition() - startPos).get() < simpleVoipPacket->getTotalLengthField())
	    stream.readByte();
	return simpleVoipPacket;
}

} // namespace inet


















