//
// Copyright (C) 2006 Andras Babos and Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/routing/ospf/v2/interface/Ospfv2InterfaceStateDown.h"
#include "inet/routing/ospf/v2/interface/Ospfv2InterfaceStateLoopback.h"
#include "inet/routing/ospf/v2/interface/Ospfv2InterfaceStateWaiting.h"
#include "inet/routing/ospf/v2/messagehandler/MessageHandler.h"
#include "inet/routing/ospf/v2/router/Ospfv2Area.h"
#include "inet/routing/ospf/v2/router/Ospfv2Router.h"

namespace inet {
namespace ospf {
namespace v2 {

void InterfaceStateWaiting::processEvent(Ospfv2Interface *intf, Ospfv2Interface::Ospfv2InterfaceEventType event)
{
    if ((event == Ospfv2Interface::BACKUP_SEEN) ||
        (event == Ospfv2Interface::WAIT_TIMER))
    {
        calculateDesignatedRouter(intf);
    }
    else if (event == Ospfv2Interface::INTERFACE_DOWN) {
        intf->reset();
        changeState(intf, new InterfaceStateDown, this);
    }
    else if (event == Ospfv2Interface::LOOP_INDICATION) {
        intf->reset();
        changeState(intf, new InterfaceStateLoopback, this);
    }
    else if (event == Ospfv2Interface::HELLO_TIMER) {
        if (intf->getType() == Ospfv2Interface::BROADCAST) {
            intf->sendHelloPacket(Ipv4Address::ALL_OSPF_ROUTERS_MCAST);
        }
        else {    // Ospfv2Interface::NBMA
            unsigned long neighborCount = intf->getNeighborCount();
            int ttl = (intf->getType() == Ospfv2Interface::VIRTUAL) ? VIRTUAL_LINK_TTL : 1;
            for (unsigned long i = 0; i < neighborCount; i++) {
                Neighbor *neighbor = intf->getNeighbor(i);
                if (neighbor->getPriority() > 0) {
                    intf->sendHelloPacket(neighbor->getAddress(), ttl);
                }
            }
        }
        intf->getArea()->getRouter()->getMessageHandler()->startTimer(intf->getHelloTimer(), intf->getHelloInterval());
    }
    else if (event == Ospfv2Interface::ACKNOWLEDGEMENT_TIMER) {
        intf->sendDelayedAcknowledgements();
    }
}

} // namespace v2
} // namespace ospf
} // namespace inet

