const createError = require('http-errors');
const express = require('express');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const cors = require('cors');
const moment = require('moment');
require('dotenv').config();

const passport = require('passport');
const { OIDCStrategy } = require('passport-azure-ad');
const SimpleOAuth2 = require('simple-oauth2');

const authRouter = require('./routes/auth');

const User = require('./models/user');

const graph = require('./graph');

const app = express();

app.use(cors());

mongoose.connect('mongodb://localhost/passport');

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

const oauth2 = SimpleOAuth2.create({
  client: {
    id: process.env.OAUTH_APP_ID,
    secret: process.env.OAUTH_APP_PASSWORD,
  },
  auth: {
    tokenHost: process.env.OAUTH_AUTHORITY,
    authorizePath: process.env.OAUTH_AUTHORIZE_ENDPOINT,
    tokenPath: process.env.OAUTH_TOKEN_ENDPOINT,
  },
});

async function signInComplete(iss, sub, profile, accessToken, refreshToken, params, done) {
  if (!profile.oid) {
    return done(new Error('No OID found in user profile.'));
  }

  try {
    const user = await graph.getUserDetails(accessToken);

    if (user) {
      // eslint-disable-next-line no-param-reassign
      profile.email = user.mail ? user.mail : user.userPrincipalName;
    }
  } catch (err) {
    return done(err);
  }

  const oauthToken = oauth2.accessToken.create(params);

  const updates = { 
    oid: profile.oid, 
    oauthToken,
    email: profile.email, 
    name: profile.displayName,
    lastlogin: moment().format(),
  };

  const options = {
    upsert: true
  };

  const user = await User.findOneAndUpdate({ oid: profile.oid }, updates, options, function (err, user) {
    if (err) {
      return done(err);
    }
  });

  return done(null, user);

}

passport.use(new OIDCStrategy(
  {
    identityMetadata: `${process.env.OAUTH_AUTHORITY}${process.env.OAUTH_ID_METADATA}`,
    clientID: process.env.OAUTH_APP_ID,
    responseType: 'code id_token',
    responseMode: 'form_post',
    redirectUrl: process.env.OAUTH_REDIRECT_URI,
    allowHttpForRedirectUrl: true,
    clientSecret: process.env.OAUTH_APP_PASSWORD,
    validateIssuer: false,
    passReqToCallback: false,
    scope: process.env.OAUTH_SCOPES.split(' '),
  },
  signInComplete,
));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  unset: 'destroy',
}));

app.use(flash());

app.use((req, res, next) => {
  res.locals.error = req.flash('error_msg');

  const errs = req.flash('error');
  errs.forEach((err) => res.locals.error.push({ message: 'An error occurred', debug: err }));
  next();
});

app.use(logger('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  if (req.user) {
    res.locals.user = req.user.profile;
  }
  next();
});

app.use('/auth', authRouter);

// catch 404 and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// error handler
app.use((err, req, res) => {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  const time = moment().format();
  console.log(`${time}: ${err}`);
  res.send(err);
});

module.exports = app;
