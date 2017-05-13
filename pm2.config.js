module.exports = {
  apps: [
    {
      name: "ExpressJWT",
      script: "./bin/www",
      watch: true,
      ignore_watch: ["node_modules", "./public"]
    }
  ]
}
