const mongoose = require('mongoose');
const Schema = mongoose.Schema;


// create User Schema
var User = new Schema({
  oid: String,
  oauthToken: Object,
  email: String,
  name: String,
});


module.exports = mongoose.model('users', User);