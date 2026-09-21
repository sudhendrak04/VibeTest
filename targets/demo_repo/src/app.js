// VibeTest demo bundle - planted FAKE secrets for the detector demo
const SUPABASE_URL = "https://demo-project.supabase.co";
const SUPABASE_SERVICE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.demosig";
const OLD_STYLE_SECRET = "sb_secret_demo0123456789abcdef";
const AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
Sentry.init({ dsn: "https://demo@o0.ingest.sentry.io/0" });
const ENV = { NODE_ENV: "development", apiBase: "/api" };
//# sourceMappingURL=app.js.map
