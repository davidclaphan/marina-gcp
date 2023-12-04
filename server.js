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
const SLIP = "Slips";
const USER = "Users";

const router = express.Router();

const CLIENT_ID = 'AuWovbf3d5L2dIxclVdrVHBX3u6v5dqW';
const CLIENT_SECRET = '-J5HUOB_tBkjhmpeb5Dkm1Y8RBHqgO1Pw8spfkmkGIZ-MpTQS3-k3ZOyIwM_fQDm';
const DOMAIN = 'dev-j7os5d7uf88tjkip.us.auth0.com';

const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: 'https://portfolio-claphand.wl.r.appspot.com',
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

/* ------------- Begin Model Functions ------------- */
function post_boat(name, type, length, owner, slip=null){
    var key = datastore.key(BOAT);
	const new_boat = { "name": name, "type": type, "length": length, "owner": owner, "slip": slip };
	return datastore.save({"key":key, "data":new_boat}).then(() => {return key});
}

function get_owner_boats(owner){
	const q = datastore.createQuery(BOAT);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore).filter( item => item.owner === owner );
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

function get_boat_names() {
    const q = datastore.createQuery(BOAT);
    return datastore.runQuery(q).then((entities) => {
        let boat_names = []
        for (let x in entities[0]) {
            boat_names.push(entities[0][x].name.toLowerCase())
        }
        return boat_names;
    });
}

function put_boat(id, name, type, length, owner, slip) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    const boat = { "name": name, "type": type, "length": length, "owner": owner, "slip": slip };
    return datastore.save({ "key": key, "data": boat }).then(() => { return key });
}

function delete_boat(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    return datastore.delete(key);
}

/**************************************SLIPS FUNCTIONS ***********************************/
function post_slip(number, current_boat=null, length, premium) {
    var key = datastore.key(SLIP);
    const new_slip = { "number": number, "current_boat": current_boat, "length": length, "premium": premium };
    return datastore.save({ "key": key, "data": new_slip }).then(() => { return key });
}

function get_slips() {
    const q = datastore.createQuery(SLIP);
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(fromDatastore);
    });
}

function get_slip(id) {
    const key = datastore.key([SLIP, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(fromDatastore);
        }
    });
}

function put_slip(id, number, current_boat, length, premium) {
    const key = datastore.key([SLIP, parseInt(id, 10)]);
    const slip = { "number": number, "current_boat": current_boat, "length": length, "premium": premium };
    return datastore.save({ "key": key, "data": slip }).then(() => { return key });
}

function delete_slip(id) {
    const key = datastore.key([SLIP, parseInt(id, 10)]);
    return datastore.delete(key);
}

/************* USER FUNCTIONS ********************/ 
function post_user(name, sub) {
    var key = datastore.key(USER);
    const new_user = { "name": name, "sub": sub };
    return datastore.save({ "key": key, "data": new_user }).then(() => { return key });
}

function get_users() {
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then((entities) => {
        let users = []
        for (let x in entities[0]) {
            users.push(entities[0][x].sub)
        }
        return users;
    });
}

function get_users_and_names() {
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(fromDatastore);
    });
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

app.post('/users', function(req, res){
    get_users()
    .then(users => {
        const user = req.body.sub
        if (users.includes(user)){
            res.status(204)
        } else {
            post_user(req.body.name, user)
        }
    });
});

app.get('/users', function(req, res){
    get_users_and_names()
    .then( users => {
        res.status(200).json(users);
    });
});
/* ------------- End Auth0 Functions ------------- */


/* ------------- Begin Controller Functions BOAT API ------------- */
router.get('/boats', checkJwt, function(req, res){
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    } else {
        const boats = get_owner_boats(req.user.sub)
	    .then( (boats) => {
            res.status(200).json(boats);
        });
    }
});

router.post('/boats', checkJwt, function(req, res){
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    } else if (req.body.name === undefined || req.body.type == undefined || req.body.length === undefined) {
        res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' })
    } else {
        get_boat_names()
        .then(boat_names => {
            const accepts = req.accepts('application/json')
            if (accepts !== 'application/json') {
                res.status(406).send('MIME Not Acceptable, application/json only')
            } else if (boat_names.includes(req.body.name.toLowerCase())) {
                res.status(403).json({ 'Error': 'Boat with this name already exists' }).end();
            } else {
                post_boat(req.body.name, req.body.type, req.body.length, req.user.sub)
                .then( key => {
                    const boat_res = {
                        id: parseInt(key.id),
                        name: req.body.name,
                        type: req.body.type,
                        length: req.body.length,
                        owner: req.user.sub,
                        slip: null,
                        self: req.protocol + "://" + req.get("host") + "/boats/" + parseInt(key.id)
                    }
                    res.location(req.protocol + "://" + req.get('host') + req.baseUrl + '/' + key.id);
                    res.status(201).json(boat_res);
                } );
            }
        });
    }
});

// PATCH all Boats NOT ALLOWED
router.patch('/boats', function (req, res) {
    res.set('Accept', 'GET, POST');
    res.status(405).end();
});

// PUT all Boats NOT ALLOWED
router.put('/boats', function (req, res) {
    res.set('Accept', 'GET, POST');
    res.status(405).end();
});

// DELETE all Boats NOT ALLOWED
router.delete('/boats', function (req, res) {
    res.set('Accept', 'GET, POST');
    res.status(405).end();
});

// Edit all attributes for a Boat
router.put('/boats/:boat_id', checkJwt, function (req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    } else {
        get_boat(req.params.boat_id)
        .then(boat => {
            const accepts = req.accepts('application/json')
            if (accepts !== 'application/json') {
                res.status(406).send('MIME Not Acceptable, application/json only')
            } else if (req.get('Content-Type') !== 'application/json') {
                res.status(415).json({ 'Error': 'The request object must be JSON format' })
            } else if (req.body.name === undefined || req.body.type == undefined || req.body.length === undefined) {
                res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes, to update individual attributes use PATCH' });
            } else if (typeof(req.body.name) !== 'string' || typeof(req.body.type) !== 'string' || typeof(req.body.length) !== 'number') {
                res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected {"name": string, "type": string, "length": number'});
            } else if (boat[0] === undefined || boat[0] === null) {
                res.status(404).json({ 'Error': 'No boat with this boat_id exists' });
            } else {
                get_boat_names()
                .then(boat_names => {
                    if (boat_names.includes(req.body.name.toLowerCase())) {
                        res.status(403).json({ 'Error': 'Boat with this name already exists' }).end();
                    } else {
                        put_boat(req.params.boat_id, req.body.name, req.body.type, req.body.length, req.user.sub, boat[0].slip)
                        res.set("Location", req.protocol + "://" + req.get("host") + "/boats/" + boat[0].id);
                        res.status(303).end(); 
                    }
                });
            }
        });
    }
});

// Edit some or all attributes for a Boat
router.patch('/boats/:boat_id', checkJwt, function (req, res) {
    if(req.get('content-type') !== 'application/json'){
        res.status(415).send('Server only accepts application/json data.')
    }
    if (req.user === undefined) {
        res.status(401).json({'Error': 'missing or invalid JWT'})
    } else {
        get_boat(req.params.boat_id)
        .then(boat => {
            const accepts = req.accepts('application/json')
            if (accepts !== 'application/json') {
                res.status(406).send('MIME Not Acceptable, application/json only')
            } else if (req.get('Content-Type') !== 'application/json') {
                res.status(415).json({ 'Error': 'The request object must be JSON format' })
            } else if (boat[0] === undefined || boat[0] === null) {
                res.status(404).json({ 'Error': 'No boat with this boat_id exists' });
            } else {
                get_boat_names()
                .then(boat_names => {
                    if (req.body.name !== undefined && typeof(req.body.name) !== 'string') {
                        res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected name to be string'});
                    } else if (req.body.type !== undefined && typeof(req.body.type) !== 'string') {
                        res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected type to be string'});
                    } else if (req.body.length !== undefined && typeof(req.body.length) !== 'number') {
                        res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected length to be number'});
                    } else if (req.body.name !== undefined && boat_names.includes(req.body.name.toLowerCase())) {
                        res.status(403).json({ 'Error': 'Boat with this name already exists' }).end();
                    } else {
                        let name = boat[0].name
                        let type = boat[0].type
                        let length = boat[0].length
                        let owner = boat[0].owner
            
                        if (req.body.name !== undefined) {
                            name = req.body.name
                        }
                        if (req.body.type !== undefined) {
                            type = req.body.type
                        }
                        if (req.body.length !== undefined) {
                            length = req.body.length
                        }
            
                        const boat_res = {
                            id: req.params.boat_id,
                            name: name,
                            type: type,
                            length: length,
                            owner: req.user.sub,
                            slip: boat[0].slip,
                            self: req.protocol + "://" + req.get("host") + "/boats/" + req.params.boat_id
                        };
                        put_boat(req.params.boat_id, name, type, length, owner, boat[0].slip)
                        res.set("Location", req.protocol + "://" + req.get("host") + "/boats/" + boat[0].id);
                        res.status(200).json(boat_res); 
                    }
                });
            }}
        );
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



/* ------------- Begin Controller Functions SLIP API ------------- */
router.post('/slips', function (req, res) {
    if (req.body.number === undefined || req.body.length === undefined || req.body.premium === undefined) {
        res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' }).end();
    } else {
        post_slip(req.body.number, req.body.current_boat, req.body.length, req.body.premium)
        .then(key => { 
            const slip_res = {
                id: key.id,
                number: parseInt(req.body.number),
                current_boat: null,
                length: req.body.length,
                premium: req.body.premium,
                self: req.protocol + "://" + req.get("host") + "/slips/" + parseInt(key.id)
            };
            res.status(201).json(slip_res)
        });
    }
});

// Get a Slip
router.get('/slips/:slip_id', function (req, res) {
    get_slip(req.params.slip_id)
    .then(slip => {
        if (slip[0] === undefined || slip[0] === null) {
            res.status(404).json({ 'Error': 'No slip with this slip_id exists' });
        } else {
            const slip_res = {
                id: parseInt(req.params.slip_id),
                number: parseInt(slip[0].number),
                current_boat: parseInt(slip[0].current_boat),
                length: parseInt(slip[0].length),
                premium: slip[0].premium,
                self: req.protocol + "://" + req.get("host") + "/slips/" + req.params.slip_id
            };
            res.status(200).json(slip_res);
        }
    });
});

// List all Slips
router.get('/slips', function (req, res) {
    const slips = get_slips()
        .then((slips) => {
            res.status(200).json(slips);
        });
});

// Edit All attributes for a Slip
router.put('/slips/:slip_id', function (req, res) {
    if (req.params.slip_id === undefined || req.params.slip_id === null) {
        res.status(400).json({ 'Error': 'slip_id is required for PATCH'})
    } else {
        get_slip(req.params.slip_id)
        .then(slip => {
            const accepts = req.accepts('application/json')
            if (accepts !== 'application/json') {
                res.status(406).send('MIME Not Acceptable, application/json only')
            } else if (slip[0] === undefined || slip[0] === null) {
                res.status(404).json({ 'Error': 'A slip with that slip_id does not exist' }); 
            } else if (req.body.number === undefined || req.body.length == undefined || req.body.premium === undefined) {
                res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' })
            } else if (typeof(req.body.number) !== 'number' || typeof(req.body.length) !== 'number' || typeof(req.body.premium) !== 'boolean') {
                res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected {"number": number, "length": number, "length": boolean'});
            } else {
                const slip_res = {
                    id: parseInt(req.params.slip_id),
                    number: parseInt(req.body.number),
                    current_boat: slip[0].current_boat,
                    length: parseInt(req.body.length),
                    premium: req.body.premium,
                    self: req.protocol + "://" + req.get("host") + "/slips/" + req.params.slip_id
                }
                put_slip(req.params.slip_id, req.body.number, slip[0].current_boat, req.body.length, req.body.premium)
                res.status(200).json(slip_res)
            };       
        });
    };
});


// Edit some or all attributes for a Slip
router.patch('/slips/:slip_id', function (req, res) {
    const accepts = req.accepts('application/json')
    if (accepts !== 'application/json') {
        res.status(406).send('MIME Not Acceptable, application/json only')
    } else if (req.get('Content-Type') !== 'application/json') {
        res.status(415).json({ 'Error': 'The request object must be JSON format' })
    } else if (req.params.slip_id === undefined || req.params.slip_id === null) {
        res.status(400).json({ 'Error': 'slip_id is required for PATCH'})
    } else {
        get_slip(req.params.slip_id)
        .then(slip => {
            if (slip[0] === undefined || slip[0] === null) {
                res.status(404).json({ 'Error': 'A slip with that slip_id does not exist' }); 
            } else if (req.body.number !== undefined && typeof(req.body.number) !== 'number') {
                res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected name to be string'});
            } else if (req.body.length !== undefined && typeof(req.body.length) !== 'number') {
                res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected length to be number'});
            } else if (req.body.premium !== undefined && typeof(req.body.premium) !== 'boolean') {
                res.status(400).json({ 'Error': 'Data in request object incorrect type. Expected type to be boolean'});
            } else {
                let number = slip[0].number
                let current_boat = slip[0].current_boat
                let length = slip[0].length
                let premium = slip[0].premium
    
                if (req.body.number !== undefined) {
                    number = req.body.number
                }
                if (req.body.length !== undefined) {
                    length = req.body.length
                }
                if (req.body.premium !== undefined) {
                    premium = req.body.premium
                }
    
                const slip_res = {
                    id: req.params.slip_id,
                    number: number,
                    current_boat: current_boat,
                    length: length,
                    premium: premium,
                    self: req.protocol + "://" + req.get("host") + "/slips/" + req.params.slip_id
                };
                put_slip(req.params.slip_id, number, current_boat, length, premium)
                res.set("Location", req.protocol + "://" + req.get("host") + "/slips/" + slip[0].id);
                res.status(200).json(slip_res); 
            }
        });
    }}
);

// Delete a Slip
router.delete('/slips/:slip_id', function (req, res) {
    get_slip(req.params.slip_id)
    .then(slip => {
        if (slip[0] === undefined || slip[0] === null) {
            res.status(404).json({ 'Error': 'No slip with this slip_id exists' }); 
        } else {
            delete_slip(req.params.slip_id).then(res.status(204).end());
        }
    });
});

// Boat Arrives at a Slip
router.put('/slips/:slip_id/:boat_id', function (req, res) {
    get_slip(req.params.slip_id)
    .then(slip => {
        if (slip[0] === undefined || slip[0] === null) {
            res.status(404).json({ 'Error': 'The specified boat and/or slip does not exist' }); 
        } else {
            get_boat(req.params.boat_id)
            .then(boat => {
                if (boat[0] === undefined || boat[0] === null) {
                    res.status(404).json({ 'Error': 'The specified boat and/or slip does not exist' }); 
                } else if (slip[0].current_boat !== null) {
                    res.status(403).json({ 'Error': 'The slip is not empty'});
                } else {
                    put_slip(parseInt(req.params.slip_id), parseInt(slip[0].number), parseInt(req.params.boat_id)).then(res.status(204).end());
                }
            });
        }       
    });
});

// Boat Departs a Slip
router.delete('/slips/:slip_id/:boat_id', function (req, res) {
    get_boat(req.params.boat_id)
    .then(boat => {
        if (boat[0] === undefined || boat[0] === null) {
            res.status(404).json({ 'Error': 'No boat with this boat_id is at the slip with this slip_id' });
        } else {
            get_slip(req.params.slip_id)
            .then(slip => {
                if (slip[0] === undefined || slip[0] === null) {
                    res.status(404).json({ 'Error': 'No slip with this slip_id exists' }); 
                } else if (slip[0].current_boat === null) {
                    res.status(404).json({ 'Error': 'The slip is already empty'});
                } else if (parseInt(slip[0].current_boat) !== parseInt(boat[0].id)) {
                    res.status(404).json({ 'Error': 'No boat with this boat_id is at the slip with this slip_id'});
                } else {
                    put_slip(parseInt(req.params.slip_id), parseInt(slip[0].number), null).then(res.status(204).end());
                }
            });
        }
    });
});
/* ------------- End Controller Functions SLIP API ------------- */

app.use('/', router);
app.enable('trust proxy');

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});