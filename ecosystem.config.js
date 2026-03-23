// ecosystem.config.js
module.exports = {
  apps: [{
    name: "teamFuego",
    script: "uv",
    args: "run uvicorn teamRojo:app --reload  --host 0.0.0.0 --port 5002 --workers 4",
    interpreter: "none",
    cwd: "/home/damian/code/TeamRojo",
  }]
}
