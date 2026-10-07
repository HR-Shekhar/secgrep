// FAKE fintech-style config for corpus tests
module.exports = {
  databaseUrl: "postgres://appuser:SuperSecretPassw0rd123@db.internal:5432/payments",
  authHeader: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.signaturepartgoeshere",
  githubToken: "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
};
