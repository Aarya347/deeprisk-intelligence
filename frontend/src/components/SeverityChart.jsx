import React from "react";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const COLORS = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#ca8a04", LOW: "#65a30d", NONE: "#94a3b8" };

export default function SeverityChart({ data }) {
  const rows = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    .map((k) => ({ name: k, count: data[k] ?? 0 }))
    .filter((r) => r.name !== "NONE" || r.count > 0);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis dataKey="name" stroke="#94a3b8" />
        <YAxis allowDecimals={false} stroke="#94a3b8" />
        <Tooltip contentStyle={{ background: "#1e293b", border: "none" }} />
        <Bar dataKey="count">
          {rows.map((r) => <Cell key={r.name} fill={COLORS[r.name]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
