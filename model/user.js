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
  password: {
    type: String,
    required: true
  },
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
  }
});

userSchema.plugin(passportLocalMongoose, {usernameField: 'username'});

module.exports = mongoose.model('User', userSchema);
