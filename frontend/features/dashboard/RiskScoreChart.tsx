"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

const COLORS = { score: "#f97316", remainder: "#1f2a37" };

export default function RiskScoreChart({ score }: { score: number }) {
  const data = [
    { name: "score", value: score },
    { name: "remainder", value: 100 - score },
  ];
  return (
    <div className="h-40 w-40">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" innerRadius={50} outerRadius={70} startAngle={90} endAngle={-270}>
            <Cell fill={COLORS.score} />
            <Cell fill={COLORS.remainder} />
          </Pie>
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
