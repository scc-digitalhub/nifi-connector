
var jwt = require('jsonwebtoken');
var axios = require('axios');
var fs = require('fs');
var https = require('https');

var JWKS_URI                 = process.env.AACJWKURL;
var CLIENT_ID                = process.env.AACCLIENTID;
var NIFI_ENDPOINT            = process.env.NIFIENDPOINT;
var CUSTOMCLAIM_ROLES        = "nifi/roles";
var NIFI_PARENT_ROOT         = "root";
var NIFI_ROLE_MANAGER        = 'ROLE_MANAGER';
var NIFI_ROLES               = ['ROLE_MONITOR', NIFI_ROLE_MANAGER];
var TYPE_PROCESS_GROUP       = "/process-groups/"; // view/modify process group flow
var TYPE_OPERATION           = "/operation/process-groups/"; // operate (run, stop, etc.) the process group
var TYPE_PROVENANCE          = "/provenance-data/process-groups/"; // view provenance events
var TYPE_DATA                = "/data/process-groups/"; // view/empty queues, view metadata, submit replays
var ACTION_READ              = "read";
var ACTION_WRITE             = "write";
var ADMIN_USER               = "admin";

const httpsAgent = new https.Agent({
  cert: fs.readFileSync('./certificates/admin-cert.pem'),
  key: fs.readFileSync('./certificates/admin-private-key.pem'),
  ca: fs.readFileSync('./certificates/nifi-cert.pem')
})

/**
* Check JWT token is present, is valid with respect to the preconfigured JWKS, and is not expired.
* If the check is passed, then return extracted claims.
*/
var extractClaims = async(context, headers, callback) => {
for (var h in headers) {
    if (h.toLowerCase() === 'authorization' && headers[h]) {
        // Expect header in the form Bearer <JWT>
        var token = headers[h].substring(headers[h].indexOf(' ')+1);
        var jwksClient = require('jwks-rsa');
        var client = jwksClient({
            jwksUri: JWKS_URI
        });
        function getKey(header, keyCallback){
            if (context.key) {
                keyCallback(null, context.key);
                return;
            }
            client.getSigningKey(header.kid, function(err, key) {
                var signingKey = key ? key.publicKey || key.rsaPublicKey : null;
                //context.logger.info('New key ' + signingKey);
                if(signingKey === null)
                    context.callback(new context.Response({message: 'Missing signing key'}, {}, 'application/json', 401));
                context.key = signingKey;
                keyCallback(null, signingKey);
            });
        }
   
        var options = { audience: CLIENT_ID };
   
        jwt.verify(token, getKey, options, function(err, decoded) {
            context.logger.infoWith('Verify jwt: claims: ', decoded);
            if (!decoded) {	
                context.callback(new context.Response({message: 'Incorrect signature: ' , err: err}, {}, 'application/json', 401));
            }
            callback(decoded);
        }); 
        return; 
    }
}
context.callback(new context.Response({message: 'Missing token'}, {}, 'application/json', 400));
} 
/**
 * Create ProcessGroup
 */
var createProcessGroup = async (parentId, processGroupName, processGroupId, assignRole, roleName, username) =>{
    if(processGroupId === 0){
        var newPGId = await createPG(parentId, processGroupName);
        await createUser(username);
        await NIFI_ROLES.reduce((p,role) => p.then(() => handleUserGroup(processGroupName + ":" + role)), Promise.resolve(null));
        await assignPolicy(newPGId, processGroupName, username);
        if(assignRole) assignRole2User(processGroupName + ":" + roleName, username, newPGId);
        return [newPGId, 0, 0]
    } else{
        await createUser(username);
        await NIFI_ROLES.reduce((p,role) => p.then(() => handleUserGroup(processGroupName + ":" + role)), Promise.resolve(null));
        await assignPolicy(processGroupId, processGroupName, username);
        if(assignRole) assignRole2User(processGroupName + ":" + roleName, username, processGroupId);
        return Promise.resolve([processGroupId, processGroupName, parentId]);
    }
}

var createPG = (parentId, processGroupName) =>{
    var objToBeSent = {'revision': {'version': 0}, 'component': {'name': processGroupName, 'position': {'x':Math.floor(Math.random()*1000), 'y':Math.floor(Math.random()*1000)}}};
    console.log("Inside PG creation of processGroupName: " + processGroupName + " " + NIFI_ENDPOINT + '/process-groups/' + parentId + '/process-groups');
    return axios.post(NIFI_ENDPOINT + '/process-groups/' + parentId + '/process-groups', objToBeSent, {httpsAgent})
        .then(response => {
            console.log("created pgid " + response.data.id);
            return response.data.id;
        })
        .catch(error => {console.log("Problem during PG creation " + error);});
}

/**
 * List ProcessGroups
 */
var getPGId = (parentId, processGroupName) => {
    console.log("Inside getPGId: " + processGroupName + " " + NIFI_ENDPOINT + '/flow/process-groups/' + parentId + '/status?recursive=false');
    return axios.get(NIFI_ENDPOINT + '/flow/process-groups/' + parentId + '/status?recursive=false',  {httpsAgent})
        .then(response => {
            var pgId = readRecursivePG(response.data.processGroupStatus.aggregateSnapshot, processGroupName);
            return [parentId, pgId];
         })
        .catch(function(err) {
            console.log('Problem in get response of recursive process groups. getPGId' + err);
        });
}

/**
 * Find the proper process group Id by checking in the descendant groups of the current node
 */
var readRecursivePG =  (pgSnapshots, processGroupName) => {
    console.log("Inside readRecursivePG: " + processGroupName);
    var currSnapShots;
    if(pgSnapshots !== null && pgSnapshots.processGroupStatusSnapshots !== null && 
        pgSnapshots != undefined && pgSnapshots.processGroupStatusSnapshots != undefined &&
        pgSnapshots.processGroupStatusSnapshots.length > 0){
        for(var i=0; i<pgSnapshots.processGroupStatusSnapshots.length; i++){
            currSnapShots = pgSnapshots.processGroupStatusSnapshots[i];
            if(currSnapShots !== null){
                var currSnap = currSnapShots.processGroupStatusSnapshot;
                if(currSnap !== null){
                    console.log("Inside readRecursivePG for pgId " + currSnap.id + " and pgName: " + currSnap.name);
                    if(currSnap.name === processGroupName){
                        console.log("ProcessGroup name found: " + currSnap.name);
                        return currSnap.id;
                    } 
                    //var ret = readRecursivePG(currSnap, processGroupName);
                    //if(ret != 0 ){
                    //    return ret;
                    //}
                }
            }
        }
    }
    return 0;
}

/**
 * Create UserGroup
 */
var handleUserGroup = (userGrpName) => {
    var objToBeSent = {'revision': {'version': 0},'component': {'identity': userGrpName}};
    return axios.post(NIFI_ENDPOINT + '/tenants/user-groups', objToBeSent, {httpsAgent})
        .then(res => {console.log('User Group ' + userGrpName + ' successfully created. ');return res.data.id;})
        .catch(err => console.log('During user Group creation. UserGroup ' + userGrpName + ' already exists. ' + err));
}

/**
 * get UserGroup
 */
var getUserGroup = (userGrpName) => {
    return axios.get(NIFI_ENDPOINT + '/tenants/user-groups', {httpsAgent})
        .then(function(res) {
            var userGrplist = res.data.userGroups;
            for(var i=0; i<userGrplist.length; i++){
                if(userGrplist[i].component.identity == userGrpName){
                    return userGrplist[i];
                }
            }
        }).catch(function(err) {
            console.log('Error during getUserGroup ' + err);
        });
}
/**
 * Create User
 */
var createUser = async(userName) => {
    var objToBeSent = {'revision': {'version': 0},'component': {'identity': userName}};
    console.log("Inside createUser...");
    await getPolicy(ACTION_READ, "/flow").then(policyUI =>{
        axios.post(NIFI_ENDPOINT + '/tenants/users', objToBeSent, {httpsAgent})
            .then(function(res) {
                console.log('User ' + userName + ' successfully created. ');
                if(policyUI != null){
                    policyUI.component.users.push({'revision': {'version': 0}, 'id': res.data.id,'component': {'identity': userName,'id': res.data.id}});
                    axios.put(NIFI_ENDPOINT + '/policies/'+ policyUI['id'], policyUI, {httpsAgent})
                        .then(result => console.log('User assigned successfully to the policy to view the UI '))
                        .catch(error => console.log('Error during user assignment to the policy to viewUI. ' + error));
                }
                return res.data.id;
            }).catch(function(err) {
                    console.log('During user creation. User ' + userName + ' already exists ' + err);
            });
    })
}

/**
 * get User
 */
var getUser = (userName) => {
    console.log("Inside getUser " + userName);
    return axios.get(NIFI_ENDPOINT + '/tenants/users', {httpsAgent})
        .then(function(res) {
            var userlist = res.data.users;
            for(var i=0; i<userlist.length; i++){
                if(userlist[i].component.identity === userName){
                    return userlist[i];
                }
            }
            return {};
        }).catch(error => {console.log(error); return {};});
    }

/**
 * Delete User
 */
var deleteUser = async (userId) => {
    console.log("Inside deleteUser " + userId);
    return axios.delete(NIFI_ENDPOINT + '/tenants/users/'+ userId + '?version=0', {httpsAgent})
        .then(function(res) {
            console.log("User " + userId + " successfully deleted")
            return {};
        }).catch(error => {console.log(error); return {};});
    }

/**
 * Update User
 */
var updateUser = async (userId, userName) => {
    console.log("Inside updateUser " + userId);
    objToBeSent = {'revision': {'version': 0}, 'id': userId,'component': {'identity': userName,'id': userId, userGroups: []} };
    return axios.put(NIFI_ENDPOINT + '/tenants/users/'+ userId, {httpsAgent})
        .then(function(res) {
            console.log("User " + userId + " successfully deleted")
            return {};
        }).catch(error => {console.log(error); return {};});
    }


/**
 * assign role to user
 */
var assignRole2User = async (role, userName, processGrpId) => {
    console.log("Inside assignRole2User...");
    var user = await getUser(userName);
    if(user !== null && user !== undefined && user != {}){
        var userGrp = await getUserGroup(role);
        userGrp.component.users.push({'revision': user.revision, "id": user.id});
        var groupId = userGrp.id;
        console.log(NIFI_ENDPOINT + '/tenants/user-groups/' + groupId);
        //assign user to usrGrp
        await axios.put(NIFI_ENDPOINT + '/tenants/user-groups/' + groupId, userGrp, {httpsAgent})
            .then(function(res) {
                console.log('User successfully assigned to the userGrp');
            }).catch(function(err) {
                    console.log('Error during  assignRole2User: assign user to usrGrp ' + err);
            });
        // assign user to policy
        var policyName = TYPE_PROCESS_GROUP + processGrpId;
        var policy = await getPolicy(ACTION_READ, policyName);
        policy.component.users.push({'revision': user.revision, "id": user.id});
        console.log(NIFI_ENDPOINT + '/policies/' + policy.id);
        await axios.put(NIFI_ENDPOINT + '/policies/' + policy.id, policy, {httpsAgent})
            .then(function(res) {
                console.log('User successfully assigned to the policy '+policyName);
            }).catch(function(err) {
                    console.log('Error during  assignRole2User: assign user to policy ' + policyName + " "+ err);
            });
    } else{
        console.log("User not found in assignRole2User");
    }
}

/**
 * Create Policy
 */
var createPolicy = async (action, resource, PGName, userGrps, userName) => {
    console.log("Inside createPolicy"); 
    var newUserGrps = prepareUG4Policy(PGName, userGrps, action);
    await getUser(ADMIN_USER).then(adminUser =>{
        var usr = {'revision': {'version': 0},'id': adminUser.id};
        var objToBeSent = {'revision': {'version': 0},'component': {'action': action, 'resource':resource, 'userGroups':newUserGrps, 'users': [usr]}};
        axios.post(NIFI_ENDPOINT + '/policies', objToBeSent, {httpsAgent})
            .then(result => {
                console.log('Policy created successfully ');
                return result.data;
            }).catch(error => {
                console.log('During createPolicy.' + error);
            });
        });
}

/**
 * Update Policy
 */
var updatePolicy = async (policy, action, resource, PGName, userGrps, userName) => {
    console.log("Inside updatePolicy"); 
    var newUserGrps = prepareUG4Policy(PGName, userGrps, action);
    await getUser(ADMIN_USER).then(adminUser =>{
        var usr = {'revision': {'version': 0},'id': adminUser.id};
        policy.component.userGroups = newUserGrps;
        policy.component.users = [usr];
        axios.put(NIFI_ENDPOINT + '/policies/' + policy.id, policy, {httpsAgent})
            .then(result => {
                console.log('Policy updated successfully ');
                return result.data;
            }) .catch(error => console.log("Error during updatePolicy " + error));
        });
}

var upsertPolicy = async (action, resource, PGName, userGrps, userName) => {
    console.log("Inside upsertPolicy " + action + " resource: " + resource);
    try{
        await getPolicy(action, resource, PGName, userGrps, userName)
            .then(result =>{
                console.log("check policy existence "); 
                if(result != null && result.component != null && result.component.resource !== resource) {
                    console.log("policy doesn't exist. creating it...");
                    createPolicy(action, resource, PGName, userGrps, userName);
                } else{
                    console.log("policy exists. updating it...");
                    updatePolicy(result, action, resource, PGName, userGrps, userName);
                }
            })
            .catch(error => error)
    } catch(error){console.log(error);}
}

/**
 * Get Policy
 */
var getPolicy = (action, resource) => {
    console.log("Inside getPolicy: " + NIFI_ENDPOINT + '/policies/' + action + resource);
    try{
        return axios.get(NIFI_ENDPOINT + '/policies/' + action + resource, {httpsAgent})
            .then(res => res.data)
            .catch(error => error);
    } catch(error){console.log(error);}
}

var assignPolicy = async (PGId, PGName, userName) => {
    var userGrps;
    return axios.get(NIFI_ENDPOINT + '/tenants/user-groups', {httpsAgent})
        .then(result => {
            console.log("listing user grps. ");
            userGrps = result.data.userGroups;
            upsertPolicy(ACTION_READ,   TYPE_PROCESS_GROUP + PGId, PGName, userGrps, userName);
            upsertPolicy(ACTION_WRITE,  TYPE_PROCESS_GROUP + PGId, PGName, userGrps, userName);
            upsertPolicy(ACTION_READ,   TYPE_PROVENANCE + PGId, PGName,userGrps, userName);
            upsertPolicy(ACTION_WRITE,  TYPE_OPERATION + PGId, PGName,userGrps, userName);
            upsertPolicy(ACTION_READ,   TYPE_DATA + PGId, PGName,userGrps, userName);
            upsertPolicy(ACTION_WRITE,  TYPE_DATA + PGId, PGName,userGrps, userName);
        })
        .catch(error => console.log('Error during getUserGroup ' + error));
    
}

var prepareUG4Policy = (processGroupName, listUG, action) =>{
    var name,id,role;
    var objGrp = {};
    var newGrps = [];
    for(var i=0; i<listUG.length; i++){
        name    = listUG[i]["component"]['identity'];
        id      = listUG[i]["id"];
        role    = name.substring(name.indexOf(":")+1);
        if(name.substring(0,name.indexOf(":")) === processGroupName){
            if(action === ACTION_READ || (action === ACTION_WRITE && role === NIFI_ROLE_MANAGER)){
                objGrp = {'revision': {'version': 0},'id': id};
                newGrps.push(objGrp);
            }
        }
    }
    return newGrps;
}

/**
 * Check the existence of process group before creating it, in order to avoid duplicates
 */
function checkExistence(parentId, processGroupName, assignRole) {
    var url = NIFI_ENDPOINT + '/flow/process-groups/' + parentId + '/status?recursive=false';
    return axios.get(url,{httpsAgent})
        .then(response => {
            var pgId = readRecursivePG(response.data.processGroupStatus.aggregateSnapshot, processGroupName);  
            return [parentId, processGroupName, pgId, assignRole]
        })
        .catch(error => [parentId, processGroupName, 0, assignRole]);
}

function runTask(result, spec, assignRole) {
    console.log("Inside runTask");
    console.log(result); console.log(assignRole);
    var parentId = "root";
    if(result != undefined && result != null) parentId = result[0];
    return checkExistence(parentId, spec, assignRole);
}

async function processGroupsUpsert(processGroupsToUpsert, roleName, username){
    const starterPromise = Promise.resolve(["root", 0, 0]);
    const action            = result => {if(Array.isArray(result)) return createProcessGroup(result[0], result[1], result[2], result[3], roleName, username)};
    var count = processGroupsToUpsert.length;
    await processGroupsToUpsert.reduce(
        (p, spec, index) => p.then((result) => runTask(result, spec, index === count-1).then(action)),
        starterPromise
    );
}

async function processGroupsList(roles, username){
    var user = await getUser(username);
    if(user != undefined && user !== null && username !== ADMIN_USER)
        await deleteUser(user.id); // updateUser(user.id, username); 
    var organizations = [];   
    var roleName = "";
    for (var org in roles) {
        console.log('Inside loop of orgs : ' + org + " " + roles[org]);                    
        roleName = roles[org];
        if(org.indexOf("->") >0){
            organizations = org.split("->");
        } else{
            organizations = [];
            organizations.push(org);
        }
        await processGroupsUpsert(organizations, roleName, username);
    }
}
exports.handler = (context, event) => {
    extractClaims(context, event.headers, function(claims) {
        try{
            // extract roles
            context.logger.infoWith('Roles from AAC for Nifi: ', claims[CUSTOMCLAIM_ROLES]);
            var name  = claims.username;
            var username = claims.email;  
            var roles = claims[CUSTOMCLAIM_ROLES];    
            var organizations = [];   
            var roleName = "";
            if(roles != undefined){
                processGroupsList(roles, username);
                context.callback(roles);
            } else{
                context.logger.infoWith('Missing roles from AAC. Check the claim mapping')
                context.callback(new context.Response({message: 'Missing roles from AAC. Check the claim mapping'}, {}, 'application/json', 500));
            } 
            context.callback(roles);
        } catch(err){
            context.logger.infoWith('NIFI call failure' + err)
            context.callback(new context.Response({message: 'NIFI call failure', err: err}, {}, 'application/json', 500));
        }
        
    });
};
