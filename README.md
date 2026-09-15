# Railway protected-app key server

Keep SERVER_SECRET only in Railway Variables.

Deploy:
railway init
railway up

Generate a public domain in Railway Networking.

Important: this protects the master secret from being embedded in the client.
It cannot make locally executed plaintext code impossible to recover.
For genuinely secret logic, keep that logic on the server and expose an API.
