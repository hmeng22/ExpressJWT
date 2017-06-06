var server = require('../app');

var chai = require('chai');
var chaiHttp = require('chai-http');
chai.use(chaiHttp);

var expect = chai.expect;

var mongoose = require('mongoose');
mongoose.Promise = global.Promise;
var db = null;

before((done) => {
  mongoose.connection.close(() => {
    mongoose.connect('mongodb://localhost/mydb-test');
    db = mongoose.connection;
    db.on('error', console.error.bind(console, 'connection error:'));
    db.once('open', function() {
      console.log('db : testing mongodb connected.');
      db.dropDatabase();
      done();
    });
  });
});

describe('Authorization :', () => {
  var token = null;

  after((done) => {
    db.dropDatabase();
    done();
  });

  it('POST / signup Sign Up', (done) => {
    chai.request(server).post('/signup').send({'username': 'test', 'email': 'test@test.test', 'password': 'test'}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      done();
    })
  });

  it('POST /signin Sign In', (done) => {
    chai.request(server).post('/signin').send({'username': 'test', 'password': 'test'}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      expect(res.body).to.have.property('token');

      token = res.body.token;
      done();
    })
  });

  it('POST /refreshtoken Refresh Token', (done) => {
    chai.request(server).post('/refreshtoken').send({'refresh_token': token.refresh_token}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      expect(res.body).to.have.property('token');

      done();
    });
  });

  it('POST /signout Sign Out', (done) => {
    chai.request(server).post('/signout').send({'token': token.access_token}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);

      done();
    })
  });
});

describe("User", () => {
  var token = null;

  before((done) => {
    chai.request(server).post('/signup').send({'username': 'test', 'email': 'test@test.test', 'password': 'test'}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);

      chai.request(server).post('/signin').send({'username': 'test', 'password': 'test'}).end((err, res) => {
        expect(err).to.be.null;
        expect(res).to.have.status(200);
        expect(res.body).to.be.an('Object');
        expect(res.body).to.have.property('success', true);
        expect(res.body).to.have.property('token');

        token = res.body.token;
        done();
      });
    })
  });

  after((done) => {
    db.dropDatabase();
    done();
  });

  it('GET /user Get User Info', (done) => {
    chai.request(server).get('/user').set('token', token.access_token).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      expect(res.body).to.have.property('user');

      done();
    });
  });

  it('POST /user Update User Info', (done) => {
    chai.request(server).post('/user').send({
      'token': token.access_token,
      'userinfo': {
        'newpassword': 'test'
      }
    }).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);

      done();
    });
  });

  var emailtoken = null;
  it('POST /reset_password Request to reset password', (done) => {
    chai.request(server).post('/reset_password').send({'email': 'test@test.test'}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      expect(res.body).to.have.property('emailtoken');

      emailtoken = res.body.emailtoken;
      done();
    });
  });

  it('GET /reset_password/:token Get reset password HTML', (done) => {
    chai.request(server).get('/reset_password/' + emailtoken).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);

      done();
    });
  });

  it('POST /reset_password/:token Post to reset password', (done) => {
    chai.request(server).post('/reset_password/' + emailtoken).send({'password': 'test'}).end((err, res) => {
      expect(err).to.be.null;
      expect(res).to.have.status(200);
      expect(res.body).to.be.an('Object');
      expect(res.body).to.have.property('success', true);
      
      done();
    })
  });
});
