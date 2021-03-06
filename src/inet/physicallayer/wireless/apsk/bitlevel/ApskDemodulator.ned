//
// Copyright (C) 2014 OpenSim Ltd.
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

package inet.physicallayer.wireless.apsk.bitlevel;

import inet.physicallayer.wireless.common.contract.bitlevel.IDemodulator;

//
// This module is part of a simple hypothetical layered receiver. It computes
// the bit domain representation from the symbol domain representation by applying
// the configured modulation.
//
// @see ~ApskModulator, ~ApskLayeredReceiver.
//
simple ApskDemodulator like IDemodulator
{
    parameters:
        string modulation; // BPSK, QPSK, QAM-16, QAM-64, QAM-256, etc. (see ApskModulationBase::findModulation)
        @display("i=block/mac");
}

