var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var cors = require('cors');
require('dotenv').config();

// model
var db = require('./model/db');
var User = require('./model/user');

// router
var index = require('./routes/index');
var apisv1 = require('./routes/apisv1');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// uncomment after placing your favicon in /public
// app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
if (process.env.IS_TESTING === "true") {
  app.use(logger('dev'));
}
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(cors());

// passport
var passport = require("passport");
var expressJwt = require('express-jwt');
app.use(passport.initialize());
app.use(passport.session());

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// authentication
// app.use('/v1/*', auth.authenticate());
var jwt = require('jsonwebtoken');
var privateSecretKey = require('fs').readFileSync('./privateSecret.key');
app.use(['/v1/*', '/user', '/signout'], expressJwt({
  secret: privateSecretKey,
  getToken: function(req) {
    // header authorization Bearer is handled by default
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    } else if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'JWT') {
      return req.headers.authorization.split(' ')[1];
    } else if (req.headers && req.headers.token) {
      return req.headers.token;
    } else if (req.body && req.body.token) {
      return req.body.token;
    } else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null;
  },
  isRevoked: function(req, payload, done) {
    User.findById(payload.user_id, (err, u) => {
      if (err) {
        return done(err);
      } else {
        if (u.access_token_valid_key == payload.access_token_valid_key) {
          return done(null, false)
        }
        return done(null, true)
      }
    })
  }
}), function(err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    res.status(401).json(err);
  }
});

// routers
app.use('/', index);
app.use('/v1', apisv1);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development'
    ? err
    : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
