module.exports = {
  apps: [
    {
      name: "ExpressJWT",
      script: "./bin/www",
      // cluster mode
      // instances: 0,
      // exec_mode: "cluster",
      watch: true,
      ignore_watch: ["node_modules", "./public"]
    }
  ]
}
