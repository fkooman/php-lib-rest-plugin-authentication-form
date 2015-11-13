# Release History

## 1.0.2 (...)
- forgot to use `BadRequestException`
- add additional unit tests
- fix `isAttempt` to not always return `true`, but only if there is 
  actually a user logged in (ignore "attempts")
- require Referrer is set, although we already have this requirement
  because of CSRF protection

## 1.0.1 (2015-10-27)
- fix a small bug where logout expects a query parameter for `redirect_to`

## 1.0.0 (2015-10-23)
- initial release
