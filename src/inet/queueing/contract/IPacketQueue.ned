//
// Copyright (C) 2020 OpenSim Ltd.
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package inet.queueing.contract;

//
// This module interface is implemented by packet queue modules. A packet queue
// is a passive module which has one passive input and one passive output.
// Packets pushed into the passive input are either stored or dropped. Packets
// pulled from the passive output are provided from the stored packets.
//
moduleinterface IPacketQueue extends IPassivePacketSink, IPassivePacketSource
{
    parameters:
        @display("i=block/queue");
}
