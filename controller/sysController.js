var path = require('path');
var async = require('async');
var crypto = require('crypto')

var passport = require('passport')
var User = require('../model/user')
var jwt = require('jsonwebtoken')
var privateSecretKey = require('fs').readFileSync('./privateSecret.key')

var transporter = require('../utils/tools').transporter
var log = require('../utils/tools').log

var sysController = {
  /**
  * @apiDefine ResponseJSON
  *
  * @apiSuccess {Boolean} success Specify if the request is successful.
  * @apiSuccess {String} message Message.
  * @apiSuccess {Object} error Error message when 'success' is false.
  */

  /**
  * @api {post} /signup 1. Sign up
  * @apiName PostSignup
  * @apiGroup Authorization
  *
  * @apiDescription Sign up will register a new user.
  *
  * @apiParam {String} username Username (Mandatory)
  * @apiParam {String} password Password (Mandatory)
  * @apiParam {String} email Email (Mandatory)
  *
  * @apiUse ResponseJSON
  */
  signup(req, res) {
    log.debug("signup() : User info :", req.body)
    User.register(new User(req.body), req.body.password, (err, user) => {
      if (err) {
        log.error("signup() : Error : ", err)
        res.json({success: false, message: 'Cant create user.', error: err})
      } else {
        log.info("signup() : Create new user successfully.")
        res.json({success: true, message: 'Create user successfully.'})
      }
    })
  },

  /**
  * @api {post} /signin 2. Sign in
  * @apiName PostSignin
  * @apiGroup Authorization
  *
  * @apiDescription Sign in needs username & password.
  *
  * @apiParam {String} username Username (Mandatory)
  * @apiParam {String} password Password (Mandatory)
  *
  * @apiUse ResponseJSON
  * @apiSuccess {Object} token Token object.
  */
  signin(req, res, next) {
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        log.error("signin() : Authenticate Error : ", err)
        return res.json({success: false, message: 'Invalid username or password.', error: err})
      }
      if (!user) {
        log.error("signin() : Cannot find the user.")
        return res.json({success: false, message: 'Cannot find the user, Invalid username or password.'})
      }

      log.info("signin() : Start to logIn.")
      req.logIn(user, (err) => {
        if (err) {
          log.error("signin() : logIn Error : ", err)
          return res.json({success: false, message: 'Fail to sign in.', error: err})
        }

        var access_token_valid_key = crypto.randomBytes(24).toString('hex')
        var payload = {
          user_id: user._id,
          access_token_valid_key: access_token_valid_key
        }

        jwt.sign(payload, privateSecretKey, {
          expiresIn: process.env.TOKEN_EXPIRATION
        }, (err, access_token) => {
          if (err) {
            log.error("signin() : Sign Access Token Error : ", err)
            return res.json({success: false, message: 'Fail to generate access token.', error: err})
          } else {
            var refresh_token_key = crypto.randomBytes(24).toString('hex')
            var refresh_token_payload = {
              user_id: user._id,
              refresh_token_key: refresh_token_key
            }
            var refresh_token_private_secret_key = crypto.randomBytes(1024).toString('hex')

            jwt.sign(refresh_token_payload, refresh_token_private_secret_key, (err, refresh_token) => {
              user.update({
                access_token_valid_key: access_token_valid_key,
                refresh_token_private_secret_key: refresh_token_private_secret_key,
                refresh_token_key: refresh_token_key
              }, (err, u) => {
                if (err) {
                  log.error("signin() : Sign Refresh Token Error : ", err)
                  return res.json({success: false, message: 'Fail to generate refresh token.', error: err})
                } else {
                  var token = {
                    token_type: 'JWT',
                    access_token: access_token,
                    expires_in: process.env.TOKEN_EXPIRATION,
                    refresh_token: refresh_token
                  }

                  log.info("signin() : Sign in Successfully.")
                  return res.json({success: true, message: 'Generate token successfully.', token: token})
                }
              })
            })
          }
        })
      })
    })(req, res, next)
  },

  /**
  * @api {post} /refreshtoken 3. Refresh Token
  * @apiName PostRefreshtoken
  * @apiGroup Authorization
  *
  * @apiDescription Refreh token requires a refresh_token.
  *
  * @apiParam {String} refresh_token refresh_token (Mandatory)
  *
  * @apiUse ResponseJSON
  * @apiSuccess {token} token info.
  */
  refreshtoken(req, res) {
    var refresh_token = req.body.refresh_token || req.query.refresh_token || req.params.refresh_token || req.headers.refresh_token

    var d = jwt.decode(refresh_token);
    if (d.user_id) {
      User.findById(d.user_id, (err, user) => {
        if (err) {
          log.error("refreshtoken() : Find User Error : ", err)
          res.json({success: false, message: 'Fail to find the user.', error: err})
        } else {
          jwt.verify(refresh_token, user.refresh_token_private_secret_key, (err, decoded) => {
            if (err) {
              log.error("refreshtoken() : Fail to verify refresh token : ", err)
              res.json({success: false, message: 'Token is invalid, fail to refresh token.', error: err})
            } else {
              if (decoded.refresh_token_key === user.refresh_token_key) {

                var payload = {
                  user_id: user._id,
                  access_token_valid_key: user.access_token_valid_key
                }

                jwt.sign(payload, privateSecretKey, {
                  expiresIn: process.env.TOKEN_EXPIRATION
                }, function(err, access_token) {
                  if (err) {
                    log.error("refreshtoken() : Fail to generate new access token. : ", err)
                    res.json({success: false, message: 'Generate token error, fail to refresh token. ', error: err})
                  } else {
                    user.update({
                      access_tokens: access_token
                    }, (err, u) => {
                      if (err) {
                        log.error("refreshtoken() : Fail to save new access token : ", err)
                        return res.json({success: false, message: 'Fail to refresh access token.', error: err})
                      } else {

                        var token = {
                          token_type: 'JWT',
                          access_token: access_token,
                          expires_in: process.env.TOKEN_EXPIRATION
                        }

                        log.info("refreshtoken() : Generate a new access token successfully.")
                        return res.json({success: true, message: 'Refresh token successfully.', token: token})
                      }
                    })
                  }
                })

              } else {
                log.error("refreshtoken() : Refresh token is invalid.")
                res.json({success: false, message: 'Token is invalid, fail to refresh token.'})
              }
            }
          })
        }
      })
    } else {
      log.error("refreshtoken() : No user id is provided.")
      res.json({success: false, message: 'Fail to refresh token, Please provide a valid User ID.'})
    }
  },

  /**
  * @api {post} /signout 4. Sign out
  * @apiName PostSignout
  * @apiGroup Authorization
  *
  * @apiDescription Sign out.
  *
  * @apiUse ResponseJSON
  */
  signout(req, res) {
    User.findById(req.user.user_id, (err, user) => {
      if (err) {
        log.error("signout() : Cannot find the user : ", err)
        res.json({success: false, message: 'The user doesn\'t exist.', error: err})
      } else {
        user.access_token_valid_key = '';

        user.save((err) => {
          if (err) {
            log.error("signout() : Fail to sign out : ", err)
            res.json({success: false, message: 'Fail to sign out.', error: err})
          } else {
            log.info("signout() : Sign out successfully.")
            req.logout()
            res.json({success: true, message: 'Sign out successfully.'})
          }
        })
      }
    });
  },

  /**
  * @api {get} /user 1. Get user info
  * @apiName GetUser
  * @apiGroup User
  *
  * @apiDescription Get user information.
  *
  * @apiParam {String} access_token access_token (Mandatory)
  *
  * @apiUse ResponseJSON
  * @apiSuccess {user} user info.
  */
  userinfo(req, res) {
    User.findById(req.user.user_id, (err, user) => {
      if (err) {
        log.error("userinfo() : Cannot find the user : ", err)
        res.json({success: false, message: 'The user doesn\'t exist.', error: err})
      } else {
        if (!user) {
          log.error("userinfo() : Cannot find the user.")
          return res.json({success: false, message: 'The access token is invalid.'})
        } else {
          var userinfo = {
            username: user.username,
            firstname: user.firstname,
            lastname: user.lastname,
            email: user.email
          }

          log.info("userinfo() : Find the user successfully.")
          res.json({success: true, message: 'Update user info successfully.', user: userinfo})
        }
      }
    })
  },

  /**
  * @api {post} /user 2. Update user info
  * @apiName PostUser
  * @apiGroup User
  *
  * @apiDescription Update user information.
  *
  * @apiParam {String} access_token access_token (Mandatory)
  * @apiParam {String} password password
  *
  * @apiUse ResponseJSON
  */
  update(req, res) {
    User.findById(req.user.user_id, (err, user) => {
      if (err) {
        log.error("update() : Cannot find the user : ", err)
        res.json({success: false, message: 'The user doesn\'t exist.', error: err})
      } else {
        log.debug("update() : New user info.", req.body)
        user.setPassword(req.body.userinfo.newpassword, () => {
          user.access_token_valid_key = '';

          user.save((err) => {
            if (err) {
              log.error("update() : Fail to update user info : ", err)
              res.json({success: false, message: 'Fail to update user info.', error: err})
            } else {
              log.info("update() : Update user info successfully.")
              res.json({success: true, message: 'Update user info successfully.'})
            }
          })
        })
      }
    })
  },

  /**
  * @api {post} /reset_password 3. Request to reset password
  * @apiName RequestResetPassword
  * @apiGroup User
  *
  * @apiDescription Request to reset password and send an email.
  *
  * @apiParam {String} email email (Mandatory)
  *
  * @apiUse ResponseJSON
  */
  reset_password(req, res) {
    async.waterfall([
      (done) => {
        User.findOne({
          email: req.body.email
        }, (err, user) => {
          if (err) {
            log.error("reset_password() : Find User Error : ", err)
            res.json({success: false, message: 'The user doesn\'t exist.'})
          } else {
            if (!user) {
              log.error("reset_password() : Cannot find the user : ", err)
              res.json({success: false, message: 'The user doesn\'t exist.'})
            } else {
              log.info("reset_password() : Find the user successfully.")
              done(null, user)
            }
          }
        })
      },
      (user, done) => {
        var reset_password_token_key = crypto.randomBytes(24).toString('hex')
        var payload = {
          user_id: user._id,
          user_email: user.email,
          reset_password_token_key: reset_password_token_key
        }
        var reset_password_private_secret_key = crypto.randomBytes(1024).toString('hex')

        user.update({
          reset_password_private_secret_key: reset_password_private_secret_key,
          reset_password_token_key: reset_password_token_key
        }, (err, u) => {
          if (err) {
            log.error("reset_password() : Fail to reset password : ", err)
            res.json({success: false, message: 'Fail to reset password.', error: err})
          } else {
            jwt.sign(payload, reset_password_private_secret_key, {
              expiresIn: '15m'
            }, (err, token) => {
              if (err) {
                log.error("reset_password() : Generate token Error : ", err)
                res.json({success: false, message: 'Generate token Error.'})
              } else {
                log.info("reset_password() : Generate token successfully.")
                done(null, user, token)
              }
            })
          }
        })
      },
      (user, token, done) => {
        log.info("reset_password() : Reset password successfully.")
        log.debug("reset_password() : Token : ", token)
        var mailOptions = {
          to: user.email,
          from: process.env.EMAIL,
          subject: 'Reset password',
          text: 'Please click on the following link, or paste this into your browser to complete the process:\n\n' + 'http://' + req.headers.host + '/reset_password/' + token + '\n\n' + 'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        }
        transporter.sendMail(mailOptions, (err) => {
          if (err) {
            log.error("reset_password() : Send Email Error : ", err)
            res.json({success: false, message: 'Fail to send the email.', error: err})
          } else {
            log.info("reset_password() : Send a Email successfully.")
            res.json({success: true, message: 'The email has been sent successfully.', emailtoken: token})
          }
        })

      }
    ], (err) => {
      if (err) {
        log.error("update() : Fail to reset password.")
        res.json({success: false, message: 'Fail to reset password.', error: err})
      }
    })
  },

  /**
  * @api {get} /reset_password 4. Get reset password Page
  * @apiName GetResetPassword
  * @apiGroup User
  *
  * @apiDescription Get reset password page.
  *
  * @apiUse ResponseJSON
  */
  get_reset_password(req, res) {
    var token = req.params.token
    var d = jwt.decode(token)
    if (d.user_id) {
      User.findById(d.user_id, (err, u) => {
        if (err) {
          log.error("get_reset_password() : Find User Error : ", err)
          res.json({success: false, message: 'Fail to find the user.', error: err})
        } else {
          jwt.verify(token, u.reset_password_private_secret_key, (err, decoded) => {
            if (err) {
              log.error("get_reset_password() : Fail to verify the token : ", err)
              res.json({success: false, message: 'Token is invalid, fail to reset password.', error: err})
            } else {
              if (decoded.reset_password_token_key === u.reset_password_token_key) {
                log.info("get_reset_password() : Render reset password page here.")
                res.render('reset_password', {
                  title: 'Reset Password',
                  host: process.env.HOST_URL,
                  token: token
                })
              } else {
                log.error("get_reset_password() : Token is invalid, fail to reset password.")
                res.json({success: false, message: 'Token is invalid, fail to reset password.'})
              }
            }
          })
        }
      })
    } else {
      log.error("get_reset_password() : No user id is provided.")
      res.json({success: false, message: 'Token is invalid, fail to reset password.'})
    }
  },

  /**
  * @api {post} /reset_password 5. Reset password
  * @apiName PostResetPassword
  * @apiGroup User
  *
  * @apiDescription Reset password.
  *
  * @apiParam {String} password password (Mandatory)
  *
  * @apiUse ResponseJSON
  * @apiSuccess {user} user info.
  */
  post_reset_password(req, res) {
    var token = req.params.token;
    async.waterfall([
      (done) => {
        var d = jwt.decode(token)
        if (d.user_id) {
          User.findById(d.user_id, (err, u) => {
            if (err) {
              log.error("post_reset_password() : Find User Error : ", err)
              res.json({success: false, message: 'Fail to find the user.', error: err})
            } else {
              jwt.verify(token, u.reset_password_private_secret_key, (err, decoded) => {
                if (err) {
                  log.error("post_reset_password() : Fail to verify the token : ", err)
                  res.json({success: false, message: 'Token is invalid, fail to reset password.', error: err})
                } else {
                  if (decoded.reset_password_token_key === u.reset_password_token_key) {
                    log.info("post_reset_password() : verify user successfully.")
                    done(null, decoded)
                  } else {
                    log.error("post_reset_password() : Token is invalid, fail to reset password.")
                    res.json({success: false, message: 'Token is invalid, fail to reset password.'})
                  }
                }
              })
            }
          })
        } else {
          log.error("post_reset_password() : No user id is provided.")
          res.json({success: false, message: 'Token is invalid, fail to reset password.'})
        }
      },
      (decoded, done) => {
        User.findOne({
          _id: decoded.user_id
        }, (err, user) => {
          if (err) {
            log.error("post_reset_password() : Find User Error : ", err)
            res.json({success: false, message: 'Fail to find the user.', error: err})
          } else {
            if (!user) {
              log.error("post_reset_password() : Cannot find the user : ", err)
              res.json({success: false, message: 'The user doesn\'t exist.', error: err})
            } else {
              // validate new password double check 2 new password
              user.setPassword(req.body.password, (err) => {
                if (err) {
                  log.error("post_reset_password() : Find User Error : ", err)
                  res.json({success: false, message: 'Reset password error.', error: err})
                } else {
                  user.reset_password_token_key = ''
                  user.reset_password_private_secret_key = ''
                  user.save((err) => {
                    if (err) {
                      log.error("post_reset_password() : Fail to reset password : ", err)
                      res.json({success: false, message: 'Fail to reset password.', error: err})
                    } else {
                      log.info("post_reset_password() : Reset password successfully.")
                      done(null, user, done)
                    }
                  })
                }
              })
            }
          }
        })
      },
      (user, done) => {
        var mailOptions = {
          to: user.email,
          from: process.env.EMAIL,
          subject: 'Your password has been changed',
          text: 'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
        }
        transporter.sendMail(mailOptions, (err) => {
          if (err) {
            log.error("post_reset_password() : Fail to send the email : ", err)
            res.json({success: false, message: 'The password has been changed, but fail to send the email.', error: err})
          } else {
            log.info("post_reset_password() : Send a Email successfully.")
            res.json({success: true, message: 'The password has be changed and an email has been sent successfully.'})
          }
        })
      }
    ], (err) => {
      if (err) {
        log.error("update() : Fail to reset password.")
        res.json({success: false, message: 'Something wrong with reseting password.', error: err})
      }
    })
  }
}

module.exports = sysController
