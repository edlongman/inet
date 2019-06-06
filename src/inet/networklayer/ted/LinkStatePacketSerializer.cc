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
#include "inet/networklayer/ted/LinkStatePacket_m.h"
#include "inet/networklayer/ted/LinkStatePacketSerializer.h"

namespace inet {

Register_Serializer(LinkStateMsg, LinkStatePacketSerializer);

void LinkStatePacketSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    throw cRuntimeError("LinkStatePacketSerializer not fully implemented yet.");
    const auto& linkStateMsg = staticPtrCast<const LinkStateMsg>(chunk);
    size_t size = linkStateMsg->getLinkInfoArraySize();
    stream.writeByte(size);
    for(size_t i = 0; i < size; ++i){
        stream.writeIpv4Address(linkStateMsg->getLinkInfo(i).advrouter);
        stream.writeIpv4Address(linkStateMsg->getLinkInfo(i).linkid);
        stream.writeIpv4Address(linkStateMsg->getLinkInfo(i).local);
        stream.writeIpv4Address(linkStateMsg->getLinkInfo(i).remote);
//        stream.writeDoubleOn64Bits(linkStateMsg->getLinkInfo(i).metric);
//        stream.writeDoubleOn64Bits(linkStateMsg->getLinkInfo(i).MaxBandwidth);
//        for(int e = 0; e < 8; ++e)
//            stream.writeDoubleOn64Bits(linkStateMsg->getLinkInfo(i).UnResvBandwidth[i]);
        stream.writeUint64Be(linkStateMsg->getLinkInfo(i).timestamp.raw());
        stream.writeUint32Be(linkStateMsg->getLinkInfo(i).sourceId);
        stream.writeUint32Be(linkStateMsg->getLinkInfo(i).messageId);
        stream.writeBit(linkStateMsg->getLinkInfo(i).state);
    }
    stream.writeBit(linkStateMsg->getRequest());
    stream.writeUint32Be(linkStateMsg->getCommand());
}

const Ptr<Chunk> LinkStatePacketSerializer::deserialize(MemoryInputStream& stream) const
{
    auto linkStateMsg = makeShared<LinkStateMsg>();
    size_t size = stream.readByte();
    linkStateMsg->setLinkInfoArraySize(size);
    TeLinkStateInfo linkInfo;
    for(size_t i = 0; i < size; ++i){
        linkInfo.advrouter = Ipv4Address(stream.readIpv4Address());
        linkInfo.linkid = Ipv4Address(stream.readIpv4Address());
        linkInfo.local = Ipv4Address(stream.readIpv4Address());
        linkInfo.remote = Ipv4Address(stream.readIpv4Address());
//        linkInfo.metric = stream.readDoubleAs64BitValue();
//        linkInfo.MaxBandwidth = stream.readDoubleAs64BitValue();
//        for(int e = 0; i < 8; ++e)
//            linkInfo.UnResvBandwidth[e] = stream.readDoubleAs64BitValue();
        linkInfo.timestamp = SimTime().setRaw(stream.readUint64Be());
        linkInfo.sourceId = stream.readUint32Be();
        linkInfo.messageId = stream.readUint32Be();
        linkInfo.state = stream.readBit();

        linkStateMsg->setLinkInfo(i, linkInfo);
    }
    linkStateMsg->setRequest(stream.readBit());
    linkStateMsg->setCommand(stream.readUint32Be());
    return linkStateMsg;
}

} // namespace inet


















