import React, { useState, useEffect } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar } from "recharts";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import "../styles.css";

function Dashboard() {
  const [threats, setThreats] = useState([]);
  const [chartData, setChartData] = useState([{ name: "Start", threats: 0 }]);

  return (
    <div className="dashboard-container">
      <h1>Cyber Threat Dashboard</h1>
      
      {/* Threat Overview */}
      <div className="threat-overview">
        <h2>Threat Overview</h2>
        <p>Threats Detected: {chartData.length - 1}</p>
        <LineChart width={300} height={150} data={chartData}>
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <CartesianGrid strokeDasharray="3 3" />
          <Line type="monotone" dataKey="threats" stroke="#ffcc00" />
        </LineChart>
      </div>

      {/* Live Cyber Threat Map */}
      <div className="threat-map">
        <h2>Live Cyber Threat Map</h2>
        <MapContainer center={[20, 0]} zoom={2} style={{ height: "500px", width: "100%" }}>
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          {threats.map((threat, index) => (
            <Marker key={index} position={[threat.location[0], threat.location[1]]}>
              <Popup>
                <b>Threat Detected!</b> <br />
                IP: {threat.source_ip} <br />
                Type: {threat.type} <br />
                Severity: {threat.severity}
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>

      {/* Recent Incidents */}
      <div className="recent-incidents">
        <h2>Recent Incidents</h2>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Source IP</th>
              <th>Type</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((threat, index) => (
              <tr key={index}>
                <td>{threat.timestamp}</td>
                <td>{threat.severity}</td>
                <td>{threat.source_ip}</td>
                <td>{threat.type}</td>
                <td>{threat.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Model Performance Metrics */}
      <div className="performance-metrics">
        <h2>Model Performance Metrics</h2>
        <BarChart width={300} height={150} data={[{ name: "Accuracy", value: 92 }, { name: "Precision", value: 85 }, { name: "Recall", value: 88 }]}>
          <XAxis dataKey="name" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="value" fill="#0074D9" />
        </BarChart>
      </div>
    </div>
  );
}

export default Dashboard;
