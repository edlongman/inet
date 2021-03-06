//
// Copyright (C) 2015 OpenSim Ltd.
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

#include "inet/physicallayer/wireless/ieee80211/mode/Ieee80211OfdmModulation.h"

#include "inet/physicallayer/wireless/common/modulation/BpskModulation.h"
#include "inet/physicallayer/wireless/common/modulation/Qam16Modulation.h"
#include "inet/physicallayer/wireless/common/modulation/Qam256Modulation.h"
#include "inet/physicallayer/wireless/common/modulation/Qam64Modulation.h"
#include "inet/physicallayer/wireless/common/modulation/QbpskModulation.h"
#include "inet/physicallayer/wireless/common/modulation/QpskModulation.h"

namespace inet {
namespace physicallayer {

Ieee80211OfdmModulation::Ieee80211OfdmModulation(const ApskModulationBase* subcarrierModulation) :
        subcarrierModulation(subcarrierModulation)
{
}

std::ostream& Ieee80211OfdmModulation::printToStream(std::ostream& stream, int level, int evFlags) const
{
    stream << "Ieee80211OfdmModulation";
    if (level <= PRINT_LEVEL_TRACE)
        stream << EV_FIELD(subcarrierModulation, printFieldToString(subcarrierModulation, level + 1, evFlags));
    return stream;
}

// Modulations
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::qbpskModulation(&QbpskModulation::singleton);
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::bpskModulation(&BpskModulation::singleton);
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::qpskModulation(&QpskModulation::singleton);
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::qam16Modulation(&Qam16Modulation::singleton);
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::qam64Modulation(&Qam64Modulation::singleton);
const Ieee80211OfdmModulation Ieee80211OfdmCompliantModulations::qam256Modulation(&Qam256Modulation::singleton);

} /* namespace physicallayer */
} /* namespace inet */
