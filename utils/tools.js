var winston = require('winston')
var loggingLevel = process.env.IS_TESTING === "true"
  ? 'error'
  : process.env.LOG_LEVEL
var winstonLogger = new(winston.Logger)({
  level: loggingLevel,
  transports: [new winston.transports.Console({
      prettyPrint: true,
      colorize: true,
      timestamp: function() {
        return moment().format('YYYY-MM-DD HH:mm:ss');
      }
    })],
  exitOnError: false
})

var nodemailer = require('nodemailer')
var transporter = nodemailer.createTransport({
  host: process.env.EMAIL_CONFIG_HOST,
  port: Number(process.env.EMAIL_CONFIG_PORT),
  secure: process.env.EMAIL_CONFIG_SECURE === "true",
  auth: {
    user: process.env.EMAIL_CONFIG_AUTH_USER,
    pass: process.env.EMAIL_CONFIG_AUTH_PASS
  },
  tls: {
    // do not fail on invalid certs
    rejectUnauthorized: process.env.EMAIL_CONFIG_TLS_REJECTUNAUTHORIZED === "true"
  }
})

module.exports = {
  log: winstonLogger,
  transporter: transporter
}
