import React from "react";
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

const META = {
  P0: { color: "#ef4444", label: "Fix now" },
  P1: { color: "#f97316", label: "Sprint" },
  P2: { color: "#eab308", label: "Backlog" },
  P3: { color: "#64748b", label: "Monitor" },
};

export default function TierPie({ data }) {
  const rows = Object.entries(META)
    .map(([tier, m]) => ({ name: `${tier} ${m.label}`, value: data[tier] ?? 0, fill: m.color }))
    .filter((r) => r.value > 0);
  if (!rows.length) return <p className="empty">No data yet.</p>;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={rows} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} paddingAngle={3}>
          {rows.map((r) => <Cell key={r.name} fill={r.fill} />)}
        </Pie>
        <Tooltip contentStyle={{ background: "#1e293b", border: "none" }} />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
