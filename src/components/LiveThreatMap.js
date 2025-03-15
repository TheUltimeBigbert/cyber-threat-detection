import React, { useEffect } from "react";
import { MapContainer, TileLayer, Marker, Polyline, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";

const threatCoordinates = [
  { lat: 37.7749, lng: -122.4194, label: "San Francisco, USA" },
  { lat: 51.5074, lng: -0.1278, label: "London, UK" },
  { lat: 35.6895, lng: 139.6917, label: "Tokyo, Japan" },
];

const LiveThreatMap = () => {
  return (
    <div className="threat-map">
      <h2>LIVE CYBER THREAT MAP</h2>
      <MapContainer center={[20, 0]} zoom={2} style={{ height: "400px", width: "100%", borderRadius: "10px" }}>
        <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
        {threatCoordinates.map((threat, index) => (
          <Marker key={index} position={[threat.lat, threat.lng]}>
            <Popup>{threat.label}</Popup>
          </Marker>
        ))}
        <Polyline
          positions={threatCoordinates.map((threat) => [threat.lat, threat.lng])}
          color="red"
        />
      </MapContainer>
    </div>
  );
};

export default LiveThreatMap;