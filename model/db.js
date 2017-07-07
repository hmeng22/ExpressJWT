var mongoose = require('mongoose');
mongoose.Promise = global.Promise;

if (process.env.IS_TESTING === "true") {
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> -------------------- <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>>   TESTING DATABASE   <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>>   TESTING DATABASE   <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>>   TESTING DATABASE   <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> -------------------- <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  mongoose.connect(process.env.MONGODB_ADDRESS_TESTING, {useMongoClient: true});
} else {
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> -------------------- <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> DEV || PROD DATABASE <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> DEV || PROD DATABASE <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> DEV || PROD DATABASE <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  console.log('>>>>>>>>>>>>>>>>>>>>>>>>>>> -------------------- <<<<<<<<<<<<<<<<<<<<<<<<<<<');
  mongoose.connect(process.env.MONGODB_ADDRESS, {useMongoClient: true});
}

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  console.log('db : mongodb connected. \n\n\n');
});
