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

package inet.visualizer.common;

import inet.visualizer.base.PacketDropVisualizerBase;
import inet.visualizer.contract.IPacketDropVisualizer;

//
// This module visualizes packet drops on a 3D osg scene. It displays an icon for
// each packet drop in the network. See the documentation of the base module for
// what constitutes a packet drop.
//
// @see ~PacketDropOsgVisualizer, ~PacketDropVisualizer, ~PacketDropVisualizerBase, ~IPacketDropVisualizer
//
simple PacketDropOsgVisualizer extends PacketDropVisualizerBase like IPacketDropVisualizer
{
    parameters:
        @class(PacketDropOsgVisualizer);
}

