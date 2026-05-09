const express = require("express");

const app = express();
app.use(express.json({ limit: "100kb" }));

app.post("/collect", (req, res) => {
  console.log("\nCaptured demo payload:");
  console.log(JSON.stringify(req.body, null, 2));
  res.json({ ok: true });
});

app.get("/", (req, res) => {
  res.send("Attacker server is running.");
});

const PORT = 4000;
app.listen(PORT, "127.0.0.1", () => {
  console.log(`Attacker server listening on http://127.0.0.1:${PORT}`);
});