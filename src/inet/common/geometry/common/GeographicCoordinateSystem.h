//
// Copyright (C) 2013 OpenSim Ltd.
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

#ifndef __INET_GEOGRAPHICCOORDINATESYSTEM_H
#define __INET_GEOGRAPHICCOORDINATESYSTEM_H

#include "inet/common/geometry/common/Coord.h"
#include "inet/common/geometry/common/Quaternion.h"

#if defined(WITH_OSGEARTH) && defined(WITH_VISUALIZERS)
#include <osgEarth/MapNode>
#endif

namespace inet {

class INET_API GeoCoord
{
  public:
    static const GeoCoord NIL;

  public:
    /** @name latitude, longitude and altitude coordinate of the position. */
    /*@{*/
    deg latitude;
    deg longitude;
    m altitude;
    /*@}*/

  public:
    GeoCoord(deg latitude, deg longitude, m altitude) : latitude(latitude), longitude(longitude), altitude(altitude) { }
};

class INET_API IGeographicCoordinateSystem
{
  public:
    virtual GeoCoord getScenePosition() const = 0;
    virtual Quaternion getSceneOrientation() const = 0;

    virtual Coord computeSceneCoordinate(const GeoCoord& geographicCoordinate) const = 0;
    virtual GeoCoord computeGeographicCoordinate(const Coord& sceneCoordinate) const = 0;
};

class INET_API SimpleGeographicCoordinateSystem : public cSimpleModule, public IGeographicCoordinateSystem
{
  protected:
    double metersPerDegree = 111320;
    deg sceneLatitude = deg(NaN);
    deg sceneLongitude = deg(NaN);
    m sceneAltitude = m(NaN);

  protected:
    virtual void initialize(int stage) override;

  public:
    virtual GeoCoord getScenePosition() const override { return GeoCoord(sceneLatitude, sceneLongitude, sceneAltitude); }
    virtual Quaternion getSceneOrientation() const override { return Quaternion::IDENTITY; }

    virtual Coord computeSceneCoordinate(const GeoCoord& geographicCoordinate) const override;
    virtual GeoCoord computeGeographicCoordinate(const Coord& sceneCoordinate) const override;
};

#if defined(WITH_OSGEARTH) && defined(WITH_VISUALIZERS)

class INET_API OsgGeographicCoordinateSystem : public cSimpleModule, public IGeographicCoordinateSystem
{
  protected:
    GeoCoord scenePosition = GeoCoord::NIL;
    Quaternion sceneOrientation = Quaternion::NIL;
    osgEarth::MapNode *mapNode = nullptr;
    osg::Matrixd locatorMatrix;
    osg::Matrixd inverseLocatorMatrix;

  protected:
    virtual void initialize(int stage) override;

  public:
    virtual GeoCoord getScenePosition() const override { return scenePosition; }
    virtual Quaternion getSceneOrientation() const override { return sceneOrientation; }

    virtual Coord computeSceneCoordinate(const GeoCoord& geographicCoordinate) const override;
    virtual GeoCoord computeGeographicCoordinate(const Coord& sceneCoordinate) const override;
};

#endif // WITH_OSGEARTH

} // namespace inet

#endif

