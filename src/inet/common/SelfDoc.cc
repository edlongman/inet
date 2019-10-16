//
// Copyright (C) 2019 OpenSim Ltd.
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
// @author: Zoltan Bojthe
//

#include <fstream>

#include "inet/common/INETDefs.h"

namespace inet {

SelfDoc globalSelfDoc;

SelfDoc::~SelfDoc()
{
    std::ofstream file;
    file.open("/tmp/SelfDoc.txt", std::ofstream::out | std::ofstream::app);
    if (file.fail())
        throw std::ios_base::failure(std::strerror(errno));

    //make sure write fails with exception if something is wrong
    file.exceptions(file.exceptions() | std::ios::failbit | std::ifstream::badbit);

    std::cout << "=SelfDoc= pre seekpos: " << file.tellp() << std::endl;
    for (const auto& elem : textSet)
        file << elem << std::endl;
    std::cout << "=SelfDoc= post seekpos: " << file.tellp() << std::endl;
    file.close();
    std::cout << "=SelfDoc= size of set: " << textSet.size() << std::endl;
}

std::string SelfDoc::kindToStr(int kind, cProperties *properties1, const char *propName1, cProperties *properties2, const char *propName2)
{
    if (properties1) {
        auto prop = properties1->get(propName1);
        if (!prop && properties2)
            prop = properties2->get(propName2);
        if (prop) {
            if (auto propValue = prop->getValue()) {
                if (auto e = omnetpp::cEnum::find(propValue)) {
                    if (auto t = e->getStringFor(kind)) {
                        std::ostringstream os;
                        os << propValue << "::" << t;
                        return os.str();
                    }
                }
            }
        }
    }
    return std::to_string(kind);
}

} // namespace inet

