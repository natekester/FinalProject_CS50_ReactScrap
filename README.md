My app keeps track of maunfacturing scrap, and then shows graphs analyzing the cost associated with the products and root causes.

the finalProject folder holds my Settings, parent urls and other management info.

the scrap_backend folder contains my backend for the app, including my models, urls and views - which accumulate to the the Api my front end uses.

The backend utilizes an sqlite database dictated by the views. 

The folder "final_project_react" contains the front end of the app. the src folder holds the main front end.
Parents: index.js->App.js->TopLayout,login,newscrap,openscrap,scrapgraph,closedscrap. From there, various other childeren are used. There is also a tracks.png used for the symbol.

The front and back end utilize JWT tokens to ensure validity of the user. the user recieves a refresh token and a short lived auth token when the individual logs in. When a user logs in, the username and password are checked against a table that has the user and hashed passwords - that use bcrypt. The refresh token is alive for a day or so - and stored in a db as a hash with the users username. When the user wishes to do something, the refresh token is used to gain an auth token, that is then used to gain access to the required db data.

The backend utilizes Auth token checking, and the front end double checks auth/ref tokens in order to make sure the individual has access to the site's data. 

