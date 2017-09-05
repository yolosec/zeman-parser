# FB app

https://developers.facebook.com/apps/


# FB access token - page access token

- Go here https://developers.facebook.com/tools/explorer/?method=POST&path=me%2Ffeed&version=v2.10&message=test2
- Obtain short lived access token
- Go here https://developers.facebook.com/tools/explorer/?method=GET&path=me%2Faccounts%3Ffields%3Dname%2Caccess_token&version=v2.10

Use long lived access token

Src:
https://www.contentecontent.com/blog/2015/05/post-from-server-to-facebook-page-with-php-sdk-4/

# User access token

For posting on users wall:

- Setup Facebook app in a way http://localhost is the site
- Add http://localhost to the app domains
- Visit the following url

https://www.facebook.com/dialog/oauth?client_id=APP_ID_NUM&scope=manage_pages,email,user_posts,publish_actions&response_type=token&redirect_uri=http://localhost

- Collect the short lived access token from the response
- Extend the token to 60 days by issuing GET request to:

https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=APP_ID&client_secret=APP_SECRET&fb_exchange_token=SHORT_LIVED_TOKEN

- Collect long lived token

Resources:

- https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow
- https://developers.facebook.com/docs/facebook-login/access-tokens/expiration-and-extension
- https://developers.facebook.com/docs/php/howto/example_access_token_from_javascript
- https://developers.facebook.com/tools/explorer/

## Graph API

- https://developers.facebook.com/docs/graph-api/using-graph-api
- https://developers.facebook.com/docs/graph-api/using-graph-api#errors

