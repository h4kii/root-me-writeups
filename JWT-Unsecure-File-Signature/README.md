
# JWT Unsecure File Signature

Challenge category : WEB-SERVER \
Difficulty : MEDIUM \
Links :  https://www.root-me.org/en/Challenges/Web-Server/JWT-Unsecure-File-Signature / http://challenge01.root-me.org:59081/

Let's analyze the challenge  : 
![](/images/1.png)

The design looks like it was drawn by a child so let's analyze the source :
![](/images/2.png)

We note that there are links , almost all of them useless because they are static html pages , except `/admin` \
![](/images/3.png)

Intercepting the request with Burp we notice that there is a cookie with a JWT token (https://jwt.io/introduction) : \
```
Cookie: session=eyJhbGciOiJIUzI1NiIsImtpZCI6ImI5MDFiYjI0LTcwMGItNGNjNi1hNzFhLWNiMjA3YWI2MTMxMyIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJpYXQiOjE2OTM3MjY5MTV9.GMHoWnEW4uwXc7bF7LwjsULTvbPG16CTm_KyjCp-Jfw
```
The server responds with a json 
```
{"Unauthorized":"You are not admin !"}
```
We try to decode the token from base64 (using https://jwt.io/#debugger-io):
![](/images/4.png)

The first attempt made was to try to crack the token signing key with HashCat or John , but unfortunately I did not get any results, so let's take a closer look at the decoded token and notice a parameter in the header : 
```
"kid": "b901bb24-700b-4cc6-a71a-cb207ab61313"
```

Kid stands for Key ID ( https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4 ) \
```
4.1.4.  "kid" (Key ID) Header Parameter

   The "kid" (key ID) Header Parameter is a hint indicating which key
   was used to secure the JWS.  This parameter allows originators to
   explicitly signal a change of key to recipients.  The structure of
   the "kid" value is unspecified.  Its value MUST be a case-sensitive
   string.  Use of this Header Parameter is OPTIONAL.

   When used with a JWK, the "kid" value is used to match a JWK "kid"
   parameter value.
```
Let us try playing with the KID parameter and create a token by entering `test` in the KID parameter and `secret` for the token signature key
![](/images/5.png)

We send the request with the token modified with Burp's Repeater
![](/images/6.png)

and we notice that the KID is not stored in a database but retrieves a file in the path `keys/[KID_FILENAME]`,so test if the file containing the signature key is readable by going to  http://challenge01.root-me.org:59081/keys/b901bb24-700b-4cc6-a71a-cb207ab61313 but we get 404 response 

At this point we know that the signature key is read from a file so let's try entering the path to a file we know : 
![](/images/2.png)

for example `static/challs/htmllecture.html`
![](/images/7.png)

let's try entering the file path with a Path Traversal `../static/challs/htmllecture.html` and as the signature key the contents of `htmllecture.html` so : `FLAG: ROUTEMI{c_le_premier_chall}`
![](/images/8.png)
![](/images/9.png)

There is a filter that removes `../` so we try to bypass it using `....//`
![](/images/10.png)
![](/images/11.png)

Great the game is done !!!