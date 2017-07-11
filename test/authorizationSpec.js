process.env.IS_TESTING = "true";
var server = require('../app');

var chai = require('chai');
var chaiHttp = require('chai-http');
chai.use(chaiHttp);

var expect = chai.expect;

var mongoose = require('mongoose');
mongoose.Promise = global.Promise;

after((done) => {
  mongoose.connection.models.User.findOneAndRemove({
    username: 'test'
  }, done);
});

describe('authorization Spec', () => {
  describe('#Authorization :', () => {
    var token = null;

    it('POST /signup Sign Up', (done) => {
      chai.request(server).post('/signup').send({'username': 'test', 'email': 'test@test.test', 'password': 'test'}).end((err, res) => {
        expect(err).to.be.null;
        expect(res).to.have.status(200);
        expect(res.body).to.be.an('Object');
        expect(res.body).to.have.property('success', true);

        done();
      });
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

  describe("#User", () => {
    var token = null;

    before((done) => {
      var test_user = {
        'username': 'test_user' + Date.now(),
        'email': Date.now() + '@test.test',
        'password': 'test_user_password'
      }
      chai.request(server).post('/signup').send(test_user).end((err, res) => {
        expect(err).to.be.null;
        expect(res).to.have.status(200);
        expect(res.body).to.be.an('Object');
        expect(res.body).to.have.property('success', true);

        chai.request(server).post('/signin').send(test_user).end((err, res) => {
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
    it('POST /reset_password Request to reset password', function(done) {
      this.timeout(4000);
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

    it('GET /reset_password/:token Get reset password HTML', function(done) {
      this.timeout(4000);
      chai.request(server).get('/reset_password/' + emailtoken).end((err, res) => {
        expect(err).to.be.null;
        expect(res).to.have.status(200);

        done();
      });
    });

    it('POST /reset_password/:token Post to reset password', function(done) {
      this.timeout(4000);
      chai.request(server).post('/reset_password/' + emailtoken).send({'password': 'test'}).end((err, res) => {
        expect(err).to.be.null;
        expect(res).to.have.status(200);
        expect(res.body).to.be.an('Object');
        expect(res.body).to.have.property('success', true);

        done();
      })
    });
  });
})
