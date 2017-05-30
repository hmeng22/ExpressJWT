var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var passportLocalMongoose = require('passport-local-mongoose');

var userSchema = new Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    default: ''
  },
  firstname: String,
  lastname: String,
  // password: String,
  username: {
    type: String,
    unique: true,
    required: true
  },
  createdate: {
    type: Date,
    default: Date.now()
  },
  lastsignindate: Date,
  role: {
    type: String,
    enum: [
      'client', 'admin'
    ],
    default: 'client'
  },
  access_token_valid_key: String,
  reset_password_private_secret_key: String,
  reset_password_token_key: String,
  refresh_token_private_secret_key: String,
  refresh_token_key: String
});

userSchema.plugin(passportLocalMongoose, {usernameField: 'username'});

module.exports = mongoose.model('User', userSchema);
