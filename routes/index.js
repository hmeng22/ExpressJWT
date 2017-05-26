var express = require('express');
var router = express.Router();
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer');

var passport = require("passport");
var User = require('../model/user');
var jwt = require('jsonwebtoken');
var privateSecretKey = require('fs').readFileSync('./privateSecret.key');

var transporter = nodemailer.createTransport('smtps://');

// User
router.post('/signup', function(req, res) {
  console.log("signup : User info :", req.body);
  User.register(new User(req.body), req.body.password, function(err, user) {
    if (err) {
      console.log("signup Error : ", err);
      res.json({success: false, message: 'Cant create user.', error: err})
    } else {
      console.log("signup  : ", user);
      res.json({success: true, user: user});
    }
  });
});

router.post('/signin', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) {
      console.log("signin Error : ", err);
       res.json({success: false, message: 'Invalid username or password.', error: err});
    }
    if (!user) {
       res.json({success: false, message: 'The user doesn\'t exist. Invalid username or password.'});
    }
    // signin successfully, return token
    req.logIn(user, function(err) {
      if (err) {
        console.log("logIn Error : ", err);
         res.json({success: false, message: 'Fail to sign in.', error: err});
      }

      var payload = {
        userid: user._id
      };
      
      jwt.sign(payload, privateSecretKey, {
        expiresIn: process.env.TOKEN_EXPIRATION
      }, function(err, token) {
        if (err) {
          console.log("Token Error : ", err);
          res.json({success: false, message: 'Fail to generate token.', error: err});
        } else {
          var refresh_token_key = crypto.randomBytes(24).toString('hex');
          var refresh_token_payload = {
            user_id: user._id,
            refresh_token_key: refresh_token_key
          };
          var refresh_token_private_secret_key = crypto.randomBytes(1024).toString('hex');

          jwt.sign(refresh_token_payload, refresh_token_private_secret_key, function(err, refresh_token) {

            user.update({
              refresh_token_private_secret_key: refresh_token_private_secret_key,
              refresh_token_key: refresh_token_key
            }, function(err, u) {
              if (err) {
                console.log("logIn Error : ", err);
                res.json({success: false, message: 'Fail to sign in.', error: err});
              } else {
                var token = {
                  token_type: 'JWT',
                  access_token: access_token,
                  expires_in: process.env.TOKEN_EXPIRATION,
                  refresh_token: refresh_token
                };

                res.json({success: true, message: 'Generate token successfully.', token: token});
              }
            });
          });
          
           res.json({success: true, message: 'Generate token successfully.', token: token});
        }
      });

    });
  })(req, res, next);
});

router.post('/refreshtoken', function(req, res) {
  var refresh_token = req.body.refresh_token || req.query.refresh_token || req.params.refresh_token || req.headers.refresh_token;

  var d = jwt.decode(refresh_token);
  if (d.user_id) {
    User.findById(d.user_id, function(err, u) {
      if (err) {
        res.json({success: false, message: 'Fail to find the user.', error: err});
      } else {
        jwt.verify(refresh_token, u.refresh_token_private_secret_key, function(err, decoded) {
          if (err) {
            res.json({success: false, message: 'Token is invalid, fail to refresh token.', error: err});
          } else {
            if (decoded.refresh_token_key === u.refresh_token_key) {

              var payload = {
                user_id: u._id
              };

              jwt.sign(payload, privateSecretKey, {
                expiresIn: process.env.TOKEN_EXPIRATION
              }, function(err, access_token) {
                if (err) {
                  res.json({success: false, message: 'Generate token error, fail to refresh token. ', error: err});
                } else {

                  var token = {
                    token_type: 'JWT',
                    access_token: access_token,
                    expires_in: process.env.TOKEN_EXPIRATION
                  };

                  res.json({success: true, message: 'Refresh token successfully.', token: token});
                }
              });

            } else {
              res.json({success: false, message: 'Token is invalid, fail to refresh token.'});
            }
          }
        });
      }
    });
  } else {
    res.json({success: false, message: 'Token is invalid, fail to refresh token.'});
  }
}),

router.get('/userinfo', function(req, res) {
  async.waterfall([
    function(done) {
      var token = req.body.token || req.query.token || req.headers['x-access-token'];
      jwt.verfiy(token, privateSecretKey, function(err, decoded) {
        if (err) {
          res.json({success: false, message: 'The token is invalid.', error: err});
        } else {
          done(decode);
        }
      });
    },
    function(decode, done) {
      User.findById(decode.user_id, function(err, user) {
        if (err) {
          res.json({success: false, message: 'The user doesn\'t exist.', error: err});
        } else {
          var userinfo = {
            username : user.username,
            firstname : user.firstname,
            lastname : user.lastname,
            email : user.email
          };

          res.json({success: true, message: 'Update user info successfully.', user: userinfo});
        }
      });
    }
  ], function(err) {
    if (err) {
      res.json({success: false, message: 'Fail to get user info.', error: err});
    }
  });
});

router.post('/update', function(req, res) {
  async.waterfall([
    function(done) {
      var token = req.body.token || req.query.token || req.headers['x-access-token'];
      jwt.verfiy(token, privateSecretKey, function(err, decoded) {
        if (err) {
          res.json({success: false, message: 'The token is invalid.', error: err});
        } else {
          done(decode);
        }
      });
    },
    function(decode, done) {
      User.findById(decode.user_id, function(err, user) {
        if (err) {
          res.json({success: false, message: 'The user doesn\'t exist.', error: err});
        } else {
          console.log("update user info here.", user, req.body.userinfo);
          user.setPassword(req.body.user.newpassword, function() {
            user.save(function(err) {
              if (err) {
                res.json({success: false, message: 'Fail to update user info.', error: err});
              } else {
                res.json({success: true, message: 'Update user info successfully.'});
              }
            });
          });
        }
      });
    }
  ], function(err) {
    if (err) {
      res.json({success: false, message: 'Fail to update user info.', error: err});
    }
  });

});

router.post('/signout', function(req, res) {
  req.logout();
  res.json({success: true, message: 'Sign out successfully.'})
});

router.post('/reset_password', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({
        email: req.body.email
      }, function(err, user) {
        if (err) {
          res.json({success: false, message: 'The user doesn\'t exist.'});
        } else {
          if (!user) {
            res.json({success: false, message: 'The user doesn\'t exist.'});
          } else {
            done(user);
          }
        }
      });
    },
    function(user, done) {
      var payload = {
        user_id : user._id,
        user_email : user.email
      };

      jwt.sign(payload, privateSecretKey, {
        expiresIn: '15m'
      }, function(err, token) {
        if (err) {
          res.json({success: false, message: 'Can\'t reset the password.'});
        } else {
          done(user, token);
        }
      });

    },
    function(user, token, done) {
      var mailOptions = {
        to: user.email,
        from: 'noreplay@public.com',
        subject: 'Reset password',
        text: 'Please click on the following link, or paste this into your browser to complete the process:\n\n' + 'http://' + req.headers.host + '/password_reset_change/' + token + '\n\n' + 'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        if (err) {
          res.json({success: false, message: 'Fail to send the email.', error: err});
        } else {
          res.json({success: true, message: 'The email has been sent successfully.'});
        }
      });
    }
  ], function(err) {
    if (err) {
      res.json({success: false, message: 'Fail to reset password.', error: err});
    }
  })
});

router.get('/reset_password/:token', function(req, res) {
  jwt.verfiy(token, privateSecretKey, function(err, decoded) {
    if (err) {
      res.json({success: false, message: 'The token is invalid.', error: err});
    } else {
      res.json({success: true, message: 'Render reset password page here.'});
    }
  });
}).post('/reset_password/:token', function(req, res) {
  async.waterfall([
    function(done) {
      jwt.verfiy(token, privateSecretKey, function(err, decoded) {
        if (err) {
          res.json({success: false, message: 'The token is invalid.', error: err});
        } else {
          done(decoded);
        }
      });
    },
    function(decoded, done) {
      User.findOne({
        _id: decoded.user_id
      }, function(err, user) {
        if (!user) {
          res.json({success: false, message: 'The user doesn\'t exist.', error: err});
        } else {

          // validate new password double check 2 new password
          user.setPassword(req.body.confirm, function() {
            user.save(function(err) {
              if (err) {
                res.json({success: false, message: 'Fail to reset password.', error: err});
              }
            });
          });

          done(user, done);
        }
      });
    },
    function(user, done) {
      var mailOptions = {
        to: user.email,
        from: 'noreplay@public.com',
        subject: 'Your password has been changed',
        text: 'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        if (err) {
          res.json({success: false, message: 'Fail to send the email.', error: err});
        } else {
          res.json({success: true, message: 'The email has been sent successfully.'});
        }
      });
    }
  ], function(err) {
    if (err) {
      res.json({success: false, message: 'Fail to reset password.', error: err});
    }
  });
});

//
//
// development

router.get('/users', function(req, res) {
  User.find({}, function(err, users) {
    res.json(users);
  });
});

router.get('/auser', function(req, res) {
  var u = new User({username: 'test', email: 'test@test.test', password: 'test'});
  User.register(new User(u), u.password, function(err, user) {
    if (err) {
      console.log("signup Error : ", err);
      res.json({success: false, message: 'Cant create user.', error: err})
    } else {
      console.log("signup  : ", user);
      res.json({success: true, user: user});
    }
  });
});

module.exports = router;
