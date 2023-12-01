const express = require('express');
const app = express();
const path = require('path');

const { auth, requiresAuth } = require('express-openid-connect');
const {Datastore} = require('@google-cloud/datastore');

const bodyParser = require('body-parser');
const datastore = new Datastore();

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');

const BOAT = "Boats";

const router = express.Router();

const CLIENT_ID = 'GQ9Evdrv7pHmJ9YRIHUj79sdDAxRz8OH';
const CLIENT_SECRET = 'BiOzbCyTBMgWCa-nAJxdajZserkdICcKQzjyGa6Y8VIX_CrCG4Mk3eHKTbTfnYRt';
const DOMAIN = 'dev-j7os5d7uf88tjkip.us.auth0.com';

const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://hw7-claphand.wl.r.appspot.com',
    clientID: `${CLIENT_ID}`,
    issuerBaseURL: `https://${DOMAIN}`,
    secret: `${CLIENT_SECRET}`
}

app.use(auth(config));
app.use(express.static(path.join(__dirname, 'views')));
app.use(bodyParser.json());

function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256'],
    credentialsRequired: false
  });

/* ------------- Begin Lodging Model Functions ------------- */
function post_boat(name, type, length, public, owner){
    var key = datastore.key(BOAT);
	const new_boat = {"name": name, "type": type, "length": length, "public": public, "owner": owner};
	return datastore.save({"key":key, "data":new_boat}).then(() => {return key});
}

function get_owner_boats(owner){
	const q = datastore.createQuery(BOAT);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore).filter( item => item.owner === owner );
		});
}

function get_public_boats(){
	const q = datastore.createQuery(BOAT);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore).filter( item => item.public === true );
		});
}

function get_owner_public_boats(owner){
	const q = datastore.createQuery(BOAT);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore).filter( item => item.owner === owner && item.public === true );
		});
}

function get_boat(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

function delete_boat(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    return datastore.delete(key);
}
/* ------------- End Model Functions ------------- */

/* ------------- Begin Auth0 Functions ------------- */
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
  });
  
app.get('/profile', requiresAuth(), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'user-info.html'));
  });

app.get('/getUserData', (req, res) => {
    // Retrieve user info with (req.oidc.user) 
    // ref: https://auth0.com/docs/quickstart/webapp/express#display-user-profile
    const userInfo = {
        name: req.oidc.user.name,
        email: req.oidc.user.email,
        sub: req.oidc.user.sub,
        JTW: req.oidc.idToken
    }
    res.json(userInfo);
  });
/* ------------- End Auth0 Functions ------------- */


/* ------------- Begin Controller Functions BOAT API ------------- */
router.get('/boats', checkJwt, function(req, res){
    if (req.user === undefined) {
        const boats = get_public_boats()
        .then ( (boats) => {
            res.status(200).json(boats);
        });
    } else {
        const boats = get_owner_boats(req.user.sub)
	    .then( (boats) => {
            res.status(200).json(boats);
        });
    };
});

router.get('/owners/:owner_id/boats', function(req, res){
    get_owner_public_boats(req.params.owner_id)
	.then( (boats) => {
        res.status(200).json(boats)
    });
});

router.post('/boats', checkJwt, function(req, res){
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    }
    else {
        post_boat(req.body.name, req.body.type, req.body.length, req.body.public, req.user.sub)
        .then( key => {
            const boat_res = {
                id: parseInt(key.id),
                name: req.body.name,
                type: req.body.type,
                length: req.body.length,
                public: req.body.public,
                owner: req.user.name
            }
            res.location(req.protocol + "://" + req.get('host') + req.baseUrl + '/' + key.id);
            res.status(201).json(boat_res);
        } );
    }
});

router.delete('/boats/:boat_id', checkJwt, function(req, res) {
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    } else {
        get_boat(req.params.boat_id)
        .then(boat => {
            if (boat[0] === undefined || boat[0] === null) {
                res.status(403).json({'Error': 'No boat with this boat_id exists'});
            } else if (boat[0].owner !== req.user.sub) {
                res.status(403).json({'Error': 'This boat_id is owned by a different user'});
            } else if (boat[0].owner === req.user.sub) {
                delete_boat(req.params.boat_id).then(res.status(204).end());
            } else {
                res.send(500).json({'Error': 'Error processing request'})
            }
        });
    };
});
/* ------------- End Controller Functions BOAT API ------------- */

app.use('/', router);
app.enable('trust proxy');

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});