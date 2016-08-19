# Release History

## 4.0.0 (2016-08-19)
- update `fkooman/rest` and `fkooman/http` dependencies

## 3.0.4 (2016-04-12)
- no longer destroy the session, but just delete all authentication 
  keys

## 3.0.3 (2016-03-25)
- update `fkooman/json`

## 3.0.2 (2016-03-07)
- fix running test on newer versions of `fkooman/tpl` dealing with 
  breaking API

## 3.0.1 (2015-12-20)
- if `login_hint` does not match currently logged in user, do not silently
  continue with the already logged in user (issue #1)

## 3.0.0 (2015-11-20)
- finish ability to show credential error in template
- improved session testing
- major cleanups
- API change for contructing the object and for template integration

## 2.0.0 (2015-11-19)
- major API update for new `fkooman/rest-plugin-authentication`

## 1.0.1 (2015-10-27)
- fix a small bug where logout expects a query parameter for `redirect_to`

## 1.0.0 (2015-10-23)
- initial release
