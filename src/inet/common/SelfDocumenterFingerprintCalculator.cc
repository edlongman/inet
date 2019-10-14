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


#include <algorithm>

#include "inet/common/ModuleAccess.h"
#include "inet/common/SelfDocumenterFingerprintCalculator.h"
#include "inet/common/packet/Packet.h"

#ifdef __INET_SELFDOC_H

namespace inet {

Register_Class(SelfDocumenterFingerprintCalculator);

static std::string tagsToString(cMessage *msg)
{
    std::set<std::string> tagSet;
    std::ostringstream os;
    auto tags = findTags(msg);
    if (tags) {
        auto cnt = tags->getNumTags();
        for (int i=0; i < cnt; i++) {
            auto tag = tags->getTag(i);
            if (tag)
                tagSet.insert(opp_typename(typeid(*tag)));
        }
    }
    for (const auto& t : tagSet) {
        if (os.tellp() > 0)
            os << ",";
        os << t;
    }
    return os.str();
}

static std::string gateInfo(cGate *gate)
{
    if (gate) {
        std::ostringstream os;
        os << gate->getName() << (gate->isVector() ? "[]" : "");
        return os.str();
    }
    else
        return "<nullptr>";
}

static bool isNum (char c) { return (c >= '0' && c <= '9'); }

void SelfDocumenterFingerprintCalculator::addEvent(cEvent *event)
{
    if (event->isMessage()) {
        cMessage *msg = static_cast<cMessage *>(event);
        auto ctrl = msg->getControlInfo();
        auto context = msg->getContextPointer();

        auto from = msg->getSenderModule();
        if (msg->isSelfMessage()) {
            std::ostringstream os;
            std::string msgName = msg->getName();
            std::replace_if(msgName.begin(), msgName.end(), isNum, 'N');
            os << "=SelfDoc=" << from->getComponentType()->getFullName()
                    << ": SCHEDULE: "
                    << " msg=" << opp_typename(typeid(*msg))
                    << " kind=" << SelfDoc::kindToStr(msg->getKind(), from->getProperties(), "selfMessageKinds", nullptr, "")
                    << " ctrl=" << (ctrl ? opp_typename(typeid(*ctrl)) : "<null>")
                    << " tags=" << tagsToString(msg)
                    << " msgname=" << msgName
                   ;
            globalSelfDoc.insert(os.str());
        }
        else {
            auto senderGate = msg->getSenderGate();
            auto arrivalGate = msg->getArrivalGate();
            if (senderGate == nullptr) {
                std::ostringstream os;
                os << "=SelfDoc=" << from->getComponentType()->getFullName()
                        << ": OUTPUTDIRECT:"
                        << " msg=" << opp_typename(typeid(*msg))
                        << " kind=" << SelfDoc::kindToStr(msg->getKind(), from->getProperties(), "directSendKinds", arrivalGate->getProperties(), "messageKinds")
                        << " ctrl=" << (ctrl ? opp_typename(typeid(*ctrl)) : "<null>")
                        << " tags=" << tagsToString(msg)
                       ;
                globalSelfDoc.insert(os.str());
            }
            else {
                std::ostringstream os;
                os << "=SelfDoc=" << from->getComponentType()->getFullName()
                        << ": OUTPUT:"
                        << " gate=" << gateInfo(senderGate)
                        << " msg=" << opp_typename(typeid(*msg))
                        << " kind=" << SelfDoc::kindToStr(msg->getKind(), senderGate->getProperties(), "messageKinds", arrivalGate->getProperties(), "messageKinds")
                        << " ctrl=" << (ctrl ? opp_typename(typeid(*ctrl)) : "<null>")
                        << " tags=" << tagsToString(msg)
                       ;
                globalSelfDoc.insert(os.str());
            }

            {
                std::ostringstream os;
                auto to = msg->getArrivalModule();
                os << "=SelfDoc=" << to->getComponentType()->getFullName()
                        << ": INPUT:"
                        << " gate=" << gateInfo(arrivalGate)
                        << " msg=" << opp_typename(typeid(*msg))
                        << " kind=" << SelfDoc::kindToStr(msg->getKind(), arrivalGate->getProperties(), "messageKinds", senderGate ? senderGate->getProperties() : nullptr, "messageKinds")
                        << " ctrl=" << (ctrl ? opp_typename(typeid(*ctrl)) : "<null>")
                        << " tags=" << tagsToString(msg)
                       ;
                globalSelfDoc.insert(os.str());
            }
        }
    }
    cSingleFingerprintCalculator::addEvent(event);
}

} // namespace

#endif // __INET_SELFDOC_H

