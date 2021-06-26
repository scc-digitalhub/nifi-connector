
var jwt = require('jsonwebtoken');
var axios = require('axios');
var fs = require('fs');
var https = require('https');
var jwksClient = require('jwks-rsa-promisified');

var JWKS_URI = process.env.AAC_JWKURL;
var CLIENT_ID = process.env.AAC_CLIENT_ID;
var CLIENT_SECRET = process.env.AAC_CLIENT_SECRET;
var AUTH = 'Basic ' + Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET, 'utf8').toString('base64');
var ISSUER = process.env.AAC_ISSUER
var NIFI_ENDPOINT = process.env.NIFI_ENDPOINT;
var CUSTOMCLAIM_ROLES = "nifi/roles";
var NIFI_PARENT_ROOT = "root";
var NIFI_ROLE_MANAGER = 'ROLE_MANAGER';
var NIFI_ROLES = ['ROLE_MONITOR', NIFI_ROLE_MANAGER];
var TYPE_PROCESS_GROUP = "/process-groups/"; // view/modify process group flow
var TYPE_OPERATION = "/operation/process-groups/"; // operate (run, stop, etc.) the process group
var TYPE_PROVENANCE = "/provenance-data/process-groups/"; // view provenance events
var TYPE_DATA = "/data/process-groups/"; // view/empty queues, view metadata, submit replays
var ACTION_READ = "read";
var ACTION_WRITE = "write";
var ADMIN_USER = "admin";

const httpsAgent = new https.Agent({
    cert: fs.readFileSync('./certificates/admin-cert.pem'),
    key: fs.readFileSync('./certificates/admin-private-key.pem'),
    ca: fs.readFileSync('./certificates/nifi-cert.pem')
})

/**
* Check JWT token is present, is valid with respect to the preconfigured JWKS, and is not expired.
* If the check is passed, then return extracted claims.
*/

async function retrieveKey(kid) {
    try {
        console.log("Retrieving Key...")
        var client = jwksClient({
            jwksUri: JWKS_URI
        });
        const key = await client.getSigningKeyAsync(kid);
        return key.publicKey || key.rsaPublicKey;
    } catch (err) {
        console.log(err.message);
        return err
    }
}

function getKid(token) {
    try {
        console.log("Getting Kid...");
        var decoded = jwt.decode(token, { complete: true });
        console.log(decoded.header);
        return decoded.header.kid;
    } catch (err) {
        console.log("Error getting kid: " + err.message);
        return err;
    }
}


function extractAuth(headers, logger) {
    try {
        var authorization = "Authorization" in headers ? headers["Authorization"] : headers["authorization"];
        if (authorization && authorization.startsWith("Basic ")) {
            return authorization.substring(authorization.indexOf(' ') + 1);
        } else {
            return null;
        }
    } catch (err) {
        logger.error(err.message)
        return null;
    }
}


async function extractClaims(body, logger) {
    try {
        if (body) {
            var js = JSON.parse(body);
            var token = js.access_token;
            var kid = getKid(token);
            var key = await retrieveKey(kid);
            var options = { audience: CLIENT_ID, issuer: ISSUER };
            var dec = await jwt.verify(token, key, options);
            return dec;
        } else {
            return null;
        }
    } catch (err) {
        logger.error(err.message)
        return null;
    }
}

/**
 * Create UserGroup
 */
async function handleUserGroup(userGrpName) {
    try {
        var objToBeSent = { 'revision': { 'version': 0 }, 'component': { 'identity': userGrpName } };
        await axios.post(NIFI_ENDPOINT + '/tenants/user-groups', objToBeSent, { httpsAgent });
    } catch (err) {
        console.log('Error during user Group creation. Assume UserGroup ' + userGrpName + ' already exists. ' + err);
    }
}

/**
 * get UserGroup
 */
async function getUserGroup(userGrpName) {
    try {
        var res = await axios.get(NIFI_ENDPOINT + '/tenants/user-groups', { httpsAgent });
        var userGrplist = res.data.userGroups;
        for (var i = 0; i < userGrplist.length; i++) {
            if (userGrplist[i].component.identity == userGrpName) {
                return userGrplist[i];
            }
        }
        return null;
    } catch (err) {
        console.log('Error during getUserGroup ' + err);
    }
}
/**
 * Create User
 */
async function createUser(userName) {
    var objToBeSent = { 'revision': { 'version': 0 }, 'component': { 'identity': userName } };
    console.log("Inside createUser...");
    var policyUI = await getPolicy(ACTION_READ, "/flow");
    try {
        var res = await axios.post(NIFI_ENDPOINT + '/tenants/users', objToBeSent, { httpsAgent });
        console.log('User ' + userName + ' successfully created. ');
        if (policyUI != null) {
            policyUI.component.users.push({ 'revision': { 'version': 0 }, 'id': res.data.id, 'component': { 'identity': userName, 'id': res.data.id } });
            await axios.put(NIFI_ENDPOINT + '/policies/' + policyUI['id'], policyUI, { httpsAgent });
            console.log('User assigned successfully to the policy to view the UI ');
        }
        return res.data.id;
    } catch (err) {
        console.log('During user creation. Assume ser ' + userName + ' already exists ' + err);
    }
}

/**
 * get User
 */
async function getUser(userName) {
    console.log("Inside getUser " + userName);
    try {
        var res = await axios.get(NIFI_ENDPOINT + '/tenants/users', { httpsAgent });
        var userlist = res.data.users;
        for (var i = 0; i < userlist.length; i++) {
            if (userlist[i].component.identity === userName) {
                return userlist[i];
            }
        }
        return null;
    } catch (err) {
        console.log(err);
        return null;
    }
}

/**
 * Delete User
 */
async function deleteUser(userId) {
    console.log("Inside deleteUser " + userId);
    try {
        var res = await axios.delete(NIFI_ENDPOINT + '/tenants/users/' + userId + '?version=0', { httpsAgent });
        console.log("User " + userId + " successfully deleted")
    } catch (err) {
        console.log(err);
    }
}

/**
 * assign role to user
 */
async function assignRole2User(role, userName, processGrpId) {
    console.log("Inside assignRole2User...");
    var user = await getUser(userName);
    if (!!user) {
        var userGrp = await getUserGroup(role);
        userGrp.component.users.push({ 'revision': user.revision, "id": user.id });
        var groupId = userGrp.id;
        //assign user to usrGrp
        try {
            var res = await axios.put(NIFI_ENDPOINT + '/tenants/user-groups/' + groupId, userGrp, { httpsAgent });
            console.log('User successfully assigned to the userGrp');
        } catch (err) {
            console.log('Error during  assignRole2User: assign user to usrGrp ' + err);
        }
        // assign user to policy
        var policyName = TYPE_PROCESS_GROUP + processGrpId;
        var policy = await getPolicy(ACTION_READ, policyName);
        policy.component.users.push({ 'revision': user.revision, "id": user.id });
        try {
            var res = await axios.put(NIFI_ENDPOINT + '/policies/' + policy.id, policy, { httpsAgent });
        } catch (err) {
            console.log('Error during  assignRole2User: assign user to policy ' + policyName + " " + err);
        }
    } else {
        console.log("User not found in assignRole2User");
    }
}


function prepareUG4Policy(processGroupName, listUG, action) {
    var name, id, role;
    var objGrp = {};
    var newGrps = [];
    for (var i = 0; i < listUG.length; i++) {
        name = listUG[i].component.identity;
        id = listUG[i].id;
        var parts = name.split(':');
        role = parts[1];
        if (parts[0] === processGroupName) {
            if (action === ACTION_READ || (action === ACTION_WRITE && role === NIFI_ROLE_MANAGER)) {
                objGrp = { 'revision': { 'version': 0 }, 'id': id };
                newGrps.push(objGrp);
            }
        }
    }
    return newGrps;
}

/**
 * Update Policy
 */
async function updatePolicy(policy, action, resource, processGroupName, userGrps, userName) {
    var newUserGrps = prepareUG4Policy(processGroupName, userGrps, action);
    try {
        var adminUser = await getUser(ADMIN_USER);
        var usr = { 'revision': { 'version': 0 }, 'id': adminUser.id };
        policy.component.userGroups = newUserGrps;
        policy.component.users = [usr];
        var result = await axios.put(NIFI_ENDPOINT + '/policies/' + policy.id, policy, { httpsAgent });
        console.log('Policy updated successfully ');
        return result.data;
    } catch (err) {
        console.log("Error during updatePolicy " + err);
    }
}
/**
 * Create Policy
 */
async function createPolicy(action, resource, processGroupName, userGrps, userName) {
    var newUserGrps = prepareUG4Policy(processGroupName, userGrps, action);
    try {
        var adminUser = await getUser(ADMIN_USER);
        var usr = { 'revision': { 'version': 0 }, 'id': adminUser.id };
        var objToBeSent = { 'revision': { 'version': 0 }, 'component': { 'action': action, 'resource': resource, 'userGroups': newUserGrps, 'users': [usr] } };
        var result = await axios.post(NIFI_ENDPOINT + '/policies', objToBeSent, { httpsAgent });
        console.log('Policy created successfully ');
        return result.data;
    } catch (err) {
        console.log('During createPolicy.' + err);
        return null;
    }
}

/**
 * Get Policy
 */
async function getPolicy(action, resource) {
    try {
        var res = await axios.get(NIFI_ENDPOINT + '/policies/' + action + resource, { httpsAgent });
        return res.data;
    } catch (error) {
        console.log('Policy ' + action + ' on ' + resource + ' not found: ' + error);
        return null;
    }
}

async function upsertPolicy(action, resource, processGroupName, userGrps, userName) {
    console.log("Inside upsertPolicy " + action + " resource: " + resource);
    try {
        var result = await getPolicy(action, resource);
        console.log("check policy existence ");
        if (!result || !!result.component && result.component.resource !== resource) {
            console.log("policy doesn't exist. creating it...");
            await createPolicy(action, resource, processGroupName, userGrps, userName);
        } else {
            console.log("policy exists. updating it...");
            await updatePolicy(result, action, resource, processGroupName, userGrps, userName);
        }
    } catch (error) {
        console.log(error);
    }
}

async function assignPolicy(processGroupId, processGroupName, userName) {
    try {
        var result = await axios.get(NIFI_ENDPOINT + '/tenants/user-groups', { httpsAgent });
        var userGrps = result.data.userGroups;
        await upsertPolicy(ACTION_READ, TYPE_PROCESS_GROUP + processGroupId, processGroupName, userGrps, userName);
        await upsertPolicy(ACTION_WRITE, TYPE_PROCESS_GROUP + processGroupId, processGroupName, userGrps, userName);
        await upsertPolicy(ACTION_READ, TYPE_PROVENANCE + processGroupId, processGroupName, userGrps, userName);
        await upsertPolicy(ACTION_WRITE, TYPE_OPERATION + processGroupId, processGroupName, userGrps, userName);
        await upsertPolicy(ACTION_READ, TYPE_DATA + processGroupId, processGroupName, userGrps, userName);
        await upsertPolicy(ACTION_WRITE, TYPE_DATA + processGroupId, processGroupName, userGrps, userName);
    } catch (err) {
        console.log('Error during assignPolicy ' + err);
    }
}

/**
 * Read all process groups
 */
async function readAllPGs(parentId, logger) {
    logger.info("Inside readAllPGs...")
    var url = NIFI_ENDPOINT + '/process-groups/' + parentId + '/process-groups';
    try {
        var response = await axios.get(url, { httpsAgent });
        return response.data.processGroups;
    } catch (e) {
        logger.error('Error reading parent group ' + e);
        return null;
    }
}
/**
 * Transform process groups into an array containing their coordinates
 */
var transformPGs = (allProcessGroups) => {
    return allProcessGroups.map(processGroup => {
        return {"id": processGroup.id, "name" : processGroup.component.name, "x" : processGroup.position.x, "y" : processGroup.position.y};
    })
}
/**
 * Create ProcessGroup
 */
async function processProcessGroup(processGroupId, processGroupName, parentId, roleName, username, processGroupsPositions) {
    console.log('processProcessGroup(' + processGroupId + ', ' + processGroupName + ')');
    if (processGroupId === 0) {
        var freePosition = findFreeGridPosition(processGroupsPositions);
        processGroupId = await createProcessGroup(parentId, processGroupName, freePosition);
        if (!processGroupId) {
            return null;
        }
        processGroupsPositions.push({"id": processGroupId, "name" : processGroupName, "x" : freePosition.col, "y" : freePosition.row})
    }
    await createUser(username);
    for (var i = 0; i < NIFI_ROLES.length; i++) {
        await handleUserGroup(processGroupName + ":" + NIFI_ROLES[i]);
    }
    await assignPolicy(processGroupId, processGroupName, username);
    await assignRole2User(processGroupName + ":" + roleName, username, processGroupId);
}

async function createProcessGroup(parentId, processGroupName, freePosition) {
    console.log('createProcessGroup(' + parentId + ', ' + processGroupName + ')');
    var objToBeSent = { 'revision': { 'version': 0 }, 'component': { 'name': processGroupName, 'position': { 'x': freePosition.col, 'y': freePosition.row } } };
    try {
        var response = await axios.post(NIFI_ENDPOINT + '/process-groups/' + parentId + '/process-groups', objToBeSent, { httpsAgent });
        return response.data.id;
    } catch (err) {
        console.log('Error creating process group ' + processGroupName + ': ' + err);
        return null;
    }
}

/**
    Find the empty position in the grid of process groups
*/
var findFreeGridPosition = (processGroupsPositions) => {
    console.log("Inside findFreeGridPosition...");
    var cols = 3;
    var cell_width = 450;
    var cell_height = 200;
    var origin = findOriginCoSystem(processGroupsPositions);
    var grid = generateGrid(processGroupsPositions, origin, cell_width, cell_height);
    console.log(grid);
    var freePosition = calculateFreeCell(grid, cols);
    freePosition["row"] = freePosition["row"] * cell_height + origin.y
    freePosition["col"] = freePosition["col"] * cell_width + origin.x
    return freePosition;
}

/**
    Find the row with the missing elements, otherwise consider adding a new row
*/
var calculateFreeCell = (grid, cols) => {
    var freePosition = grid.reduce((freePos, elem, index) => {
        if(elem.length < cols) return {"row" : index, "col" : elem.length}
        else{
            for(i=0;i<elem.length; i++){
                if(elem[i] == null || elem[i] == undefined)
                    return {"row" : index, "col" : i}
            }
        }
        return freePos
    }, {"row" : grid.length, "col" : 0});
    return freePosition;
}

/**
    Calculate the origin point of the coordinate system
*/
var findOriginCoSystem = (processGroupsPositions) => {
    var origin = processGroupsPositions.reduce((orig, elem)=>{
        if(elem.x < orig.x) orig.x = elem.x;
        if(elem.y < orig.y) orig.y = elem.y;
        return orig;
    }, {"x":Number.MAX_VALUE, "y":Number.MAX_VALUE});
    if(processGroupsPositions.length < 1) origin = {"x":0, "y":0};
    return origin;
}

/**
    Generate the matrix of the existing process groups
*/
var generateGrid = (processGroupsPositions, origin, cell_width, cell_height) => {
    var WIDTH = 390;
    var HEIGHT = 185;
    var grid = new Array();
    var x_left, x_right, y_top, y_bottom, temp, left_dist, top_dist;
    processGroupsPositions.forEach(pg => {
        left_dist = pg.x - origin.x;
        x_left = Math.floor(left_dist / cell_width);
        top_dist = pg.y - origin.y;
        y_top = Math.floor(top_dist / cell_height);
        temp = !!grid[y_top] ? grid[y_top] : new Array();
        if(!!!temp[x_left]) temp[x_left] = pg.name; else temp[x_left] += ", " + pg.name;
        x_right = left_dist + WIDTH;
        if(x_right > (x_left + 1) * cell_width){
            if(!!!temp[x_left+1]) temp[x_left+1] = pg.name; else temp[x_left+1] += ", " + pg.name;
        }
        grid[y_top] = temp;

        y_bottom = top_dist + HEIGHT;
        if(y_bottom > (y_top + 1) * cell_height){
            temp = !!grid[y_top + 1] ? grid[y_top + 1] : new Array();
            if(!!!temp[x_left]) temp[x_left] = pg.name; else temp[x_left] += ", " + pg.name
            if(x_right > (x_left + 1) * cell_width)
                if(!!!temp[x_left+1]) temp[x_left+1] = pg.name; else temp[x_left+1] += ", " + pg.name
            grid[y_top + 1] = temp;
        }
    });
    return grid;
}

/*
 * Elaborate tenant request: create group, add user to group, and create policies
 */
async function processGroupsUpsert(groupToInsert, parentId, roleName, username, processGroupsPositions) {
    var id = await checkExistence(groupToInsert, processGroupsPositions);
    await processProcessGroup(id, groupToInsert, parentId, roleName, username, processGroupsPositions);
}

/**
 * Check the existence of process group before creating it, in order to avoid duplicates
 * Find the proper process group Id by checking in the descendant groups of the current node
 */
var checkExistence = (processGroupName, processGroups) => {
    console.log("Inside checkExistence of: " + processGroupName);
    var wantedPG = processGroups.filter(pg => pg.name === processGroupName);
    return wantedPG.length > 0 ? wantedPG[0]["id"] : 0;
}

/*
 * Elaborate tenant list request: create groups, add user to groups, and create policies
 */
async function processGroupsList(roles, username, logger) {
    // check and delete user (non admin)
    var user = await getUser(username);
    if (!!user && username !== ADMIN_USER) {
        await deleteUser(user.id);
    }
    var rootId = NIFI_PARENT_ROOT;
    // get all existing processGroups under root
    var allProcessGroups = await readAllPGs(rootId, logger);
    // map the existing processGroups into a different format
    var processGroupsPositions = transformPGs(allProcessGroups);
    var organizations = [];
    var roleName = "";
    for (var org in roles) {
        roleName = roles[org];
        await processGroupsUpsert(org, rootId, roleName, username, processGroupsPositions);
    }
}

async function preProvision(claims, logger) {
    try {
        // extract roles
        logger.infoWith('Roles from AAC for Nifi: ', claims[CUSTOMCLAIM_ROLES]);
        var name = claims.username;
        var username = claims.email;
        var roles = claims[CUSTOMCLAIM_ROLES];
        var organizations = [];
        var roleName = "";
        if (roles != undefined && Object.keys(roles).length > 0) {
            await processGroupsList(roles, username, logger);
            return roles;
        } else {
            return null;
        }
    } catch (err) {
        return err;
    }
}

async function processEvent(event, logger) {
    logger.info("Inside processEvent...");

    var auth = 'Basic ' + extractAuth(event.headers, logger)
    if (auth != AUTH) {
        throw Error("Invalid authentication");
    }

    var body = event.body.toString();
    var claims = await extractClaims(body, logger);
    if (claims == null) {
        throw Error("Invalid claims or token provided");
    }

    var roles = await preProvision(claims, logger);
    if (roles == null) {
        throw Error("Invalid roles in claims");
    }

    return roles;
}

exports.handler = function (context, event) {
    var logger = context.logger;
    processEvent(event, logger)
        .then(roles => {
            var response = new context.Response({ message: 'Roles updated' }, {}, 'application/json', 200);
            context.callback(response)
        })
        .catch(err => {
            logger.error(err);
            context.callback(new context.Response({ message: 'Call failure', err: err }, {}, 'application/json', 500));
        });
};
