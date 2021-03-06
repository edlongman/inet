//
// Copyright (C) 2016 OpenSim Ltd.
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

#ifndef __INET_INDICATORLABELFIGURE_H
#define __INET_INDICATORLABELFIGURE_H

#include "inet/common/INETMath.h"
#include "inet/common/figures/IIndicatorFigure.h"

namespace inet {

class INET_API IndicatorLabelFigure : public cLabelFigure, public IIndicatorFigure
{
  protected:
    std::string textFormat = "%g";
    double value = NaN;

  protected:
    virtual const char **getAllowedPropertyKeys() const override;
    virtual void parse(cProperty *property) override;
    virtual void refresh();

  public:
    explicit IndicatorLabelFigure(const char *name = nullptr) : cLabelFigure(name) {}
    virtual const Point getSize() const override { return getBounds().getSize(); }
    virtual void setValue(int series, simtime_t timestamp, double value) override;
    virtual const char *getTextFormat() const { return textFormat.c_str(); }
    virtual void setTextFormat(const char *textFormat) { this->textFormat = textFormat; refresh(); }
};

} // namespace inet

#endif

