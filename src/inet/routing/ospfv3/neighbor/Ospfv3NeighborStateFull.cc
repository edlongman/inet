/*
 *
 * SEQUENCE_NUMBER_MISMATCH - new state EXSTART
 * BAD_LS_REQ - new state EXSTART
 * KILL_NBR - new state DOWN
 * LL_DOWN - new state DOWN
 * ADJACENCY_OK? - of yes, stay, if not, it should be destroyed and the new state should be 2WAY
 * INACTIVITY_TIMER - new state DOWN
 * 1WAY_RECEIVED - new state INIT
 * 2WAY_RECEIVED - no change
 */

#include "inet/routing/ospfv3/neighbor/Ospfv3NeighborStateFull.h"

#include "inet/routing/ospfv3/neighbor/Ospfv3Neighbor.h"
#include "inet/routing/ospfv3/neighbor/Ospfv3NeighborState2Way.h"
#include "inet/routing/ospfv3/neighbor/Ospfv3NeighborStateDown.h"
#include "inet/routing/ospfv3/neighbor/Ospfv3NeighborStateExStart.h"
#include "inet/routing/ospfv3/neighbor/Ospfv3NeighborStateInit.h"

namespace inet {
namespace ospfv3 {

void Ospfv3NeighborStateFull::processEvent(Ospfv3Neighbor *neighbor, Ospfv3Neighbor::Ospfv3NeighborEventType event)
{
    if ((event == Ospfv3Neighbor::KILL_NEIGHBOR) || (event == Ospfv3Neighbor::LINK_DOWN)) {
        neighbor->reset();
        neighbor->getInterface()->getArea()->getInstance()->getProcess()->clearTimer(neighbor->getInactivityTimer());
//        changeState(neighbor, new Ospfv3NeighborStateDown, this);
    }
    if (event == Ospfv3Neighbor::INACTIVITY_TIMER) {
        neighbor->reset();
        if (neighbor->getInterface()->getType() == Ospfv3Interface::NBMA_TYPE)
            neighbor->getInterface()->getArea()->getInstance()->getProcess()->setTimer(neighbor->getPollTimer(), neighbor->getInterface()->getPollInterval());

        changeState(neighbor, new Ospfv3NeighborStateDown, this);
    }
    if (event == Ospfv3Neighbor::ONEWAY_RECEIVED) {
        neighbor->reset();
        changeState(neighbor, new Ospfv3NeighborStateInit, this);
    }
    if (event == Ospfv3Neighbor::HELLO_RECEIVED) {
        neighbor->getInterface()->getArea()->getInstance()->getProcess()->clearTimer(neighbor->getInactivityTimer());
        neighbor->getInterface()->getArea()->getInstance()->getProcess()->setTimer(neighbor->getInactivityTimer(), neighbor->getInterface()->getDeadInterval());
    }
    if (event == Ospfv3Neighbor::IS_ADJACENCY_OK) {
        EV_DEBUG << "Ospfv3Neighbor::IS_ADJACENCY_OK caught in FullState\n";
        if (!neighbor->needAdjacency()) {
            neighbor->reset();
            changeState(neighbor, new Ospfv3NeighborState2Way, this);
        }
    }
    if ((event == Ospfv3Neighbor::SEQUENCE_NUMBER_MISMATCH) || (event == Ospfv3Neighbor::BAD_LINK_STATE_REQUEST)) {
        EV_DEBUG << "Ospfv3Neighbor::SEQUENCE_NUMBER_MISMATCH or BAD_LINK_STATE_REQUEST caught in FullState\n";
        neighbor->reset();
        neighbor->incrementDDSequenceNumber();
        neighbor->sendDDPacket(true);
        neighbor->getInterface()->getArea()->getInstance()->getProcess()->setTimer(neighbor->getDDRetransmissionTimer(), neighbor->getInterface()->getRetransmissionInterval());
        changeState(neighbor, new Ospfv3NeighborStateExStart, this);
    }
    if (event == Ospfv3Neighbor::UPDATE_RETRANSMISSION_TIMER) {
        EV_DEBUG << "Ospfv3Neighbor::UPDATE_RETRANSMISSION_TIMER caught in FullState\n";
        if (!neighbor->isRetransmissionListEmpty())
        {
            neighbor->retransmitUpdatePacket();
            neighbor->startUpdateRetransmissionTimer();
            EV_DEBUG << "retransmission done, Timer active again\n";
        }
        else {
            if (neighbor->isUpdateRetransmissionTimerActive())
                neighbor->clearUpdateRetransmissionTimer();
        }
        EV_DEBUG << "END\n";
    }
    if (event == Ospfv3Neighbor::DD_RETRANSMISSION_TIMER) {
        EV_DEBUG << "Ospfv3Neighbor::DD_RETRANSMISSION_TIMER caught in FullState\n";
        neighbor->deleteLastSentDDPacket();
    }
}

} // namespace ospfv3
}//namespace inet

