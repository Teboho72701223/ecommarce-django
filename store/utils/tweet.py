
# We will be using a mixture of requests and
# requests-oauthlib to make tweets.
from requests_oauthlib import OAuth1Session
import json # NOT IN PDF THOUGH but referenced

class Tweet:
    CONSUMER_KEY = 'mebcVMFRquNAFtm21pDfvvp3G'
    CONSUMER_SECRET = 'vNogpuhmmhosQpYHXvl32qEcDlpCZDuWFWDb16kx3N6UmxR8QQ'
    _instance = None  # NOT INCLUDED IN THE PDF

    def authenticate(self):
        # Get request token
        request_token_url = "https://api.twitter.com/oauth/request_token?oauth_callback=oob&x_auth_access_type=write"
        oauth = OAuth1Session(self.CONSUMER_KEY, client_secret=self.CONSUMER_SECRET)
        try:
            fetch_response = oauth.fetch_request_token(request_token_url)
        except ValueError:
            print("There may have been an issue with the consumer_key or consumer_secret you entered.")
            return  # Exiting the method if the exception is caught - not in content

        resource_owner_key = fetch_response.get("oauth_token")
        resource_owner_secret = fetch_response.get("oauth_token_secret")
        print("Got OAuth token: %s" % resource_owner_key)

        # Get authorization
        base_authorization_url = "https://api.twitter.com/oauth/authorize"
        authorization_url = oauth.authorization_url(base_authorization_url)
        print("Please go here and authorize: %s" % authorization_url)
        verifier = input("Paste the PIN here: ")

        # Get the access token
        access_token_url = "https://api.twitter.com/oauth/access_token"
        oauth = OAuth1Session(self.CONSUMER_KEY,
                              client_secret=self.CONSUMER_SECRET,
                              resource_owner_key=resource_owner_key,
                              resource_owner_secret=resource_owner_secret,
                              verifier=verifier,
                              )
        oauth_tokens = oauth.fetch_access_token(access_token_url)

        access_token = oauth_tokens["oauth_token"]
        access_token_secret = oauth_tokens["oauth_token_secret"]

        # Make the request
        self.oauth = OAuth1Session(
            self.CONSUMER_KEY,
            client_secret=self.CONSUMER_SECRET,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret,
        )

    def make_tweet(self, tweet):
        if self.oauth:
            # Making the request
            response = self.oauth.post(
                "https://api.twitter.com/2/tweets",
                json=tweet,
            )
        else:
            raise ValueError("Authentication failed!")

        if response.status_code != 201:
            raise Exception(
                "Request returned an error: {} {}".format(response.status_code, response.text)
            )

        print("Response code: {}".format(response.status_code))

        # Saving the response as JSON
        json_response = response.json()
        print(json.dumps(json_response, indent=4, sort_keys=True))

    def __new__(cls):
        if cls._instance is None:
            print("Creating the object")
            cls._instance = super(Tweet, cls).__new__(cls)
            cls._instance.authenticate()
            # Put any initialisation here.
        return cls._instance
