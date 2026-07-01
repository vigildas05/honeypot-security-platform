import dotenv from "dotenv";

dotenv.config();

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: Number(process.env.BACKEND_PORT ?? 8000),
  databaseUrl:
    process.env.DATABASE_URL ??
    "postgresql://honeypot:honeypot_password@localhost:5432/honeypot",
  corsOrigins: (process.env.CORS_ORIGINS ?? "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim()),
  jwtSecret: process.env.JWT_SECRET_KEY ?? "dev-only-change-me",
  dashboardUser: process.env.DASHBOARD_ADMIN_USERNAME ?? "admin",
  dashboardPassword: process.env.DASHBOARD_ADMIN_PASSWORD ?? "admin123",
  honeypotApiToken: process.env.HONEYPOT_API_TOKEN ?? "dev-honeypot-token"
};
