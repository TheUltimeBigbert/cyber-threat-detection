import React from "react";
import { ComposableMap, Geographies, Geography, Line } from "react-simple-maps";

const ThreatMap = () => {
  return (
    <div className="map-container">
      <h3>Live Cyber Threat Map</h3>
      <ComposableMap>
        <Geographies geography="/path-to-world-geojson">
          {({ geographies }) => geographies.map((geo) => <Geography key={geo.rsmKey} geography={geo} />)}
        </Geographies>
        <Line from={[102.1, 14.6]} to={[120.9, 14.6]} stroke="red" strokeWidth={2} />
      </ComposableMap>
    </div>
  );
};

export default ThreatMap;
